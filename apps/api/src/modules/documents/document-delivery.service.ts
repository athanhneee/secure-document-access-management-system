import {
  Injectable,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
  Optional,
} from '@nestjs/common';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateAccessSessionInput } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentPepService, type PepEvaluationResult } from './document-pep.service.js';
import { OfficeConverterService } from './office-converter.service.js';
import {
  WatermarkEngineService,
  type WatermarkUserData,
  type WatermarkDocumentData,
} from '../watermarks/watermark-engine.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

interface DownloadTicketEntry {
  documentId: string;
  sessionId: string;
  userId: bigint;
  principal: AuthPrincipal;
  createdAt: number;
  expiresAt: number;
}

export interface DeliveryFileResult {
  buffer: Buffer;
  mimeType: string;
  filename: string;
  fileSizeBytes: number;
  outputSha256Hash: string;
  watermarkToken?: string | undefined;
}

@Injectable()
export class DocumentDeliveryService {
  private readonly database: PrismaClient;
  private readonly ticketTtlSeconds: number;
  private readonly downloadTickets = new Map<string, DownloadTicketEntry>();

  constructor(
    private readonly pep: DocumentPepService,
    private readonly storage: ObjectStorageService,
    private readonly encryption: DocumentEncryptionService,
    private readonly officeConverter: OfficeConverterService,
    private readonly watermarkEngine: WatermarkEngineService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    config: AppConfigService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.ticketTtlSeconds = config.get('DOWNLOAD_TICKET_TTL_SECONDS') ?? 60;
  }

  /**
   * 1. Create a controlled access session via PEP.
   */
  async createSession(
    documentId: string,
    input: CreateAccessSessionInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<PepEvaluationResult> {
    return await this.pep.enforceAccess(documentId, principal, context, {
      action: input.action,
      grantId: input.grantId,
      deviceFingerprint: input.deviceFingerprint,
    });
  }

  /**
   * 2. Stream preview of a PDF document (with watermark overlay).
   * Supports optional pageNumber for page-by-page controlled streaming.
   * Requirement: Never returns raw unwatermarked file for documents requiring watermark.
   */
  async getPreviewPdf(
    documentId: string,
    sessionId: string,
    pageNumber: number | undefined,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DeliveryFileResult> {
    const now = new Date();

    // 1. Validate session
    const session = await this.database.accessSession.findUnique({
      where: { id: sessionId },
      include: {
        document_versions: {
          include: {
            document: {
              include: {
                classification_history: {
                  where: { effective_to: null },
                  include: { classification_levels: true },
                },
              },
            },
          },
        },
      },
    });

    if (!session) {
      throw new NotFoundException({
        errorCode: AppErrorCode.SESSION_NOT_FOUND,
        message: 'Access session was not found.',
      });
    }

    if (session.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: `Session is no longer active (status: ${session.status}).`,
      });
    }

    if (session.user_id !== principal.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_USER_MISMATCH,
        message: 'Session does not belong to the calling user.',
      });
    }

    if (session.document_versions.document_id !== documentId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Session is not associated with this document.',
      });
    }

    // 2. Real-time grant verification (Zero Trust: independent of worker)
    await this.grantsService.assertGrantValidForAccess(
      session.access_grant_id,
      principal.userId,
      'VIEW',
      now,
    );

    // Update session last activity
    await this.database.accessSession.update({
      where: { id: sessionId },
      data: { last_activity_at: now },
    });

    const docVersion = session.document_versions;
    const document = docVersion.document;
    const currentClassification = document.classification_history[0];
    const requireWatermark =
      currentClassification?.classification_levels?.require_watermark ?? true;

    // 3. Fetch encrypted document bytes from storage
    const encryptedBytes = await this.storage.getObject(
      this.storage.documentsBucket,
      docVersion.storage_key,
    );

    // 4. Authenticated decryption to private temporary file
    const decrypted = await this.encryption.decryptToTempFile(
      encryptedBytes,
      docVersion.encryption_key_ref,
    );

    let pdfBuffer: Buffer;
    try {
      const rawPlaintext = await fsp.readFile(decrypted.tempFilePath);

      // 5. Office to PDF conversion if needed
      const ext = docVersion.original_filename.split('.').pop()?.toLowerCase();
      if (ext === 'pdf') {
        pdfBuffer = rawPlaintext;
      } else if (['docx', 'xlsx', 'pptx'].includes(ext ?? '')) {
        pdfBuffer = await this.officeConverter.convertOfficeToPdf(
          rawPlaintext,
          docVersion.original_filename,
        );
      } else {
        throw new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: `Cannot preview format .${ext}`,
        });
      }
    } finally {
      // Securely delete plaintext temp file immediately
      await decrypted.cleanup();
    }

    let finalPdfBuffer = pdfBuffer;
    let watermarkToken: string | undefined;
    let outputSha256Hash = crypto.createHash('sha256').update(finalPdfBuffer).digest('hex');

    // 6. Apply visible watermark if required
    if (requireWatermark) {
      const config = await this.watermarkEngine.getWatermarkConfig(
        currentClassification?.classification_level_id,
      );

      // Check for existing watermark instance in this session
      const existingInstance = await this.database.watermarkInstance.findFirst({
        where: {
          access_session_id: sessionId,
          document_version_id: docVersion.id,
        },
      });

      const user = await this.database.user.findUnique({
        where: { id: principal.userId },
        select: { id: true, username: true, full_name: true, employee_code: true },
      });

      const userData: WatermarkUserData = {
        id: principal.userId,
        username: principal.username,
        fullName: user?.full_name ?? undefined,
        employeeCode: user?.employee_code ?? undefined,
      };

      const docData: WatermarkDocumentData = {
        id: document.id,
        documentCode: document.document_code,
        title: document.title,
        classificationName: currentClassification?.classification_levels?.name,
        requireWatermark: true,
      };

      const wmResult = await this.watermarkEngine.applyWatermarkToPdf(
        pdfBuffer,
        userData,
        docData,
        config,
        existingInstance?.watermark_token,
        now,
      );

      finalPdfBuffer = wmResult.watermarkedBuffer;
      watermarkToken = wmResult.watermarkToken;
      outputSha256Hash = wmResult.outputSha256Hash;

      // Persist watermark instance if not recorded yet
      if (!existingInstance) {
        await this.watermarkEngine.recordWatermarkInstance({
          watermarkConfigId: config.id,
          accessSessionId: sessionId,
          documentVersionId: docVersion.id,
          userId: principal.userId,
          watermarkToken: wmResult.watermarkToken,
          renderedText: wmResult.renderedText,
          outputSha256Hash: wmResult.outputSha256Hash,
          generatedAt: now,
        });

        await this.audit.record(
          {
            action: 'WATERMARK_GENERATED',
            outcome: 'SUCCESS',
            documentId,
            sessionId,
            details: {
              token: wmResult.watermarkToken,
              outputSha256Hash: wmResult.outputSha256Hash,
            },
          },
          principal,
          context,
        );
      }
    }

    // 7. Page extraction if pageNumber specified
    if (pageNumber !== undefined) {
      finalPdfBuffer = await this.watermarkEngine.extractPdfPage(finalPdfBuffer, pageNumber);
      outputSha256Hash = crypto.createHash('sha256').update(finalPdfBuffer).digest('hex');
    }

    // 8. Audit DOCUMENT_PREVIEWED
    await this.audit.record(
      {
        action: 'DOCUMENT_PREVIEWED',
        outcome: 'SUCCESS',
        documentId,
        sessionId,
        details: {
          pageNumber: pageNumber ?? 1,
          sizeBytes: finalPdfBuffer.length,
          outputSha256Hash,
        },
      },
      principal,
      context,
    );

    return {
      buffer: finalPdfBuffer,
      mimeType: 'application/pdf',
      filename: `preview-${document.document_code || document.id.slice(0, 8)}.pdf`,
      fileSizeBytes: finalPdfBuffer.length,
      outputSha256Hash,
      watermarkToken,
    };
  }

  /**
   * 3. Download watermarked document with strict DOWNLOAD permission checks.
   * Requirement 7: Only works if grant has DOWNLOAD and policy does not forbid download.
   * Requirement 8: Watermarked derivative with no-store headers.
   */
  async downloadDocument(
    documentId: string,
    sessionId: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DeliveryFileResult> {
    const now = new Date();

    // 1. Validate session
    const session = await this.database.accessSession.findUnique({
      where: { id: sessionId },
      include: {
        document_versions: {
          include: {
            document: {
              include: {
                classification_history: {
                  where: { effective_to: null },
                  include: { classification_levels: true },
                },
              },
            },
          },
        },
      },
    });

    if (!session) {
      throw new NotFoundException({
        errorCode: AppErrorCode.SESSION_NOT_FOUND,
        message: 'Access session was not found.',
      });
    }

    if (session.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: `Session is no longer active (status: ${session.status}).`,
      });
    }

    if (session.user_id !== principal.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_USER_MISMATCH,
        message: 'Session does not belong to the calling user.',
      });
    }

    if (session.document_versions.document_id !== documentId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Session is not associated with this document.',
      });
    }

    // 2. Strict DOWNLOAD permission check at runtime
    await this.grantsService.assertGrantValidForAccess(
      session.access_grant_id,
      principal.userId,
      'DOWNLOAD',
      now,
    );

    const docVersion = session.document_versions;
    const document = docVersion.document;
    const currentClassification = document.classification_history[0];

    // Check classification allow_download
    if (!currentClassification?.classification_levels?.allow_download) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        message: 'Document classification level does not allow downloads.',
      });
    }

    const requireWatermark =
      currentClassification?.classification_levels?.require_watermark ?? true;

    // 3. Fetch encrypted document bytes
    const encryptedBytes = await this.storage.getObject(
      this.storage.documentsBucket,
      docVersion.storage_key,
    );

    // 4. Authenticated decryption to private temporary file
    const decrypted = await this.encryption.decryptToTempFile(
      encryptedBytes,
      docVersion.encryption_key_ref,
    );

    let fileBuffer: Buffer;
    let mimeType = docVersion.mime_type;
    let filename = docVersion.original_filename;
    let watermarkToken: string | undefined;

    try {
      const rawPlaintext = await fsp.readFile(decrypted.tempFilePath);

      if (requireWatermark) {
        // Document requires watermark: deliver watermarked PDF derivative
        const ext = docVersion.original_filename.split('.').pop()?.toLowerCase();
        let pdfForWatermark: Buffer = rawPlaintext;

        if (ext !== 'pdf') {
          // Office file: convert to PDF first
          pdfForWatermark = Buffer.from(
            await this.officeConverter.convertOfficeToPdf(
              rawPlaintext,
              docVersion.original_filename,
            ),
          );
        }

        const config = await this.watermarkEngine.getWatermarkConfig(
          currentClassification?.classification_level_id,
        );

        const user = await this.database.user.findUnique({
          where: { id: principal.userId },
          select: { id: true, username: true, full_name: true, employee_code: true },
        });

        const userData: WatermarkUserData = {
          id: principal.userId,
          username: principal.username,
          fullName: user?.full_name ?? undefined,
          employeeCode: user?.employee_code ?? undefined,
        };

        const docData: WatermarkDocumentData = {
          id: document.id,
          documentCode: document.document_code,
          title: document.title,
          classificationName: currentClassification?.classification_levels?.name,
          requireWatermark: true,
        };

        const wmResult = await this.watermarkEngine.applyWatermarkToPdf(
          pdfForWatermark,
          userData,
          docData,
          config,
          undefined,
          now,
        );

        fileBuffer = wmResult.watermarkedBuffer;
        mimeType = 'application/pdf';
        filename = `${document.document_code || 'doc'}-watermarked.pdf`;
        watermarkToken = wmResult.watermarkToken;

        // Record watermark instance
        await this.watermarkEngine.recordWatermarkInstance({
          watermarkConfigId: config.id,
          accessSessionId: sessionId,
          documentVersionId: docVersion.id,
          userId: principal.userId,
          watermarkToken: wmResult.watermarkToken,
          renderedText: wmResult.renderedText,
          outputSha256Hash: wmResult.outputSha256Hash,
          generatedAt: now,
        });

        await this.audit.record(
          {
            action: 'WATERMARK_GENERATED',
            outcome: 'SUCCESS',
            documentId,
            sessionId,
            details: {
              token: wmResult.watermarkToken,
              outputSha256Hash: wmResult.outputSha256Hash,
            },
          },
          principal,
          context,
        );
      } else {
        // Watermark not required: deliver decrypted original file bytes
        fileBuffer = rawPlaintext;
      }
    } finally {
      await decrypted.cleanup();
    }

    const outputSha256Hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // 5. Audit DOCUMENT_DOWNLOADED
    await this.audit.record(
      {
        action: 'DOCUMENT_DOWNLOADED',
        outcome: 'SUCCESS',
        documentId,
        sessionId,
        details: {
          filename,
          sizeBytes: fileBuffer.length,
          outputSha256Hash,
        },
      },
      principal,
      context,
    );

    return {
      buffer: fileBuffer,
      mimeType,
      filename,
      fileSizeBytes: fileBuffer.length,
      outputSha256Hash,
      watermarkToken,
    };
  }

  /**
   * 4. Generate a short-lived, single-use download ticket bound to session.
   * Requirement 8: One-time or very short TTL (60s).
   */
  async createDownloadTicket(
    documentId: string,
    sessionId: string,
    principal: AuthPrincipal,
    _context: RequestContext,
  ): Promise<{ ticket: string; expiresAt: string; ttlSeconds: number }> {
    // Verify session belongs to user and is ACTIVE
    const session = await this.database.accessSession.findUnique({
      where: { id: sessionId },
    });

    if (!session || session.status !== 'ACTIVE' || session.user_id !== principal.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: 'Active session required to generate download ticket.',
      });
    }

    const ticket = `DT-${crypto.randomBytes(32).toString('hex')}`;
    const now = Date.now();
    const expiresAtMs = now + this.ticketTtlSeconds * 1000;

    this.downloadTickets.set(ticket, {
      documentId,
      sessionId,
      userId: principal.userId,
      principal,
      createdAt: now,
      expiresAt: expiresAtMs,
    });

    return {
      ticket,
      expiresAt: new Date(expiresAtMs).toISOString(),
      ttlSeconds: this.ticketTtlSeconds,
    };
  }

  /**
   * 5. Redeem single-use download ticket.
   * Ticket is consumed immediately (one-time use).
   */
  async redeemDownloadTicket(ticket: string, context: RequestContext): Promise<DeliveryFileResult> {
    const entry = this.downloadTickets.get(ticket);
    if (!entry) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOWNLOAD_TICKET_INVALID,
        message: 'Download ticket is invalid or has already been used.',
      });
    }

    // Immediately consume ticket (Single-Use Guarantee)
    this.downloadTickets.delete(ticket);

    if (Date.now() > entry.expiresAt) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOWNLOAD_TICKET_EXPIRED,
        message: 'Download ticket has expired.',
      });
    }

    return await this.downloadDocument(entry.documentId, entry.sessionId, entry.principal, context);
  }
}
