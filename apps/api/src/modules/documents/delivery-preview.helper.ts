/**
 * Module: Watermarked PDF Preview Pipeline Helper
 * Algorithm: Re-verifies real-time `VIEW` grant, decrypts ciphertext into an ephemeral file cleaned in `finally`,
 *   converts Office binaries to PDF, embeds session-stable forensic watermarks, and extracts single pages on demand.
 */
import { BadRequestException } from '@nestjs/common';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import { PDFDocument } from 'pdf-lib';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type {
  WatermarkDocumentData,
  WatermarkEngineService,
  WatermarkUserData,
} from '../watermarks/watermark-engine.service.js';
import type { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import type { DocumentEncryptionService } from './document-encryption.service.js';
import type { DocumentPepService } from './document-pep.service.js';
import type { ObjectStorageService } from './object-storage.service.js';
import type { OfficeConverterService } from './office-converter.service.js';
import { loadValidatedDeliverySession, type DeliveryFileResult } from './delivery-ticket.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Session-Bound Watermarked Preview & Page Slice Pipeline
 */
export async function executeWatermarkedPreview(params: {
  database: PrismaClient;
  pep: DocumentPepService;
  storage: ObjectStorageService;
  encryption: DocumentEncryptionService;
  officeConverter: OfficeConverterService;
  watermarkEngine: WatermarkEngineService;
  grantsService: AccessGrantsService;
  audit: DocumentDeliveryAuditService;
  documentId: string;
  sessionId: string;
  pageNumber: number | undefined;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<DeliveryFileResult> {
  const {
    database,
    pep,
    storage,
    encryption,
    officeConverter,
    watermarkEngine,
    grantsService,
    audit,
    documentId,
    sessionId,
    pageNumber,
    principal,
    context,
  } = params;
  const now = new Date();

  const session = await loadValidatedDeliverySession({
    database,
    pep,
    sessionId,
    documentId,
    principal,
    context,
    now,
    requireDownloadPolicy: false,
  });

  await grantsService.assertGrantValidForAccess(
    session.access_grant_id,
    principal.userId,
    'VIEW',
    now,
    documentId,
  );

  await database.accessSession.update({
    where: { id: sessionId },
    data: { last_activity_at: now },
  });

  const docVersion = session.document_versions;
  const document = docVersion.document;
  const currentClassification = document.classification_history[0];
  const requireWatermark = currentClassification?.classification_levels?.require_watermark ?? true;

  const encryptedBytes = await storage.getObject(storage.documentsBucket, docVersion.storage_key);
  const decrypted = await encryption.decryptToTempFile(
    encryptedBytes,
    docVersion.encryption_key_ref,
  );

  let pdfBuffer: Buffer;
  try {
    const rawPlaintext = await fsp.readFile(decrypted.tempFilePath);
    const ext = docVersion.original_filename.split('.').pop()?.toLowerCase();
    if (ext === 'pdf') {
      pdfBuffer = rawPlaintext;
    } else if (['docx', 'xlsx', 'pptx'].includes(ext ?? '')) {
      pdfBuffer = await officeConverter.convertOfficeToPdf(
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
    await decrypted.cleanup();
  }

  let finalPdfBuffer = pdfBuffer;
  let watermarkToken: string | undefined;
  let outputSha256Hash = crypto.createHash('sha256').update(finalPdfBuffer).digest('hex');

  if (requireWatermark) {
    const config = await watermarkEngine.getWatermarkConfig(
      currentClassification?.classification_level_id,
    );
    const existingInstance = await database.watermarkInstance.findFirst({
      where: { access_session_id: sessionId, document_version_id: docVersion.id },
    });
    const user = await database.user.findUnique({
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

    const wmResult = await watermarkEngine.applyWatermarkToPdf(
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

    if (!existingInstance) {
      await watermarkEngine.recordWatermarkInstance({
        watermarkConfigId: config.id,
        accessSessionId: sessionId,
        documentVersionId: docVersion.id,
        userId: principal.userId,
        watermarkToken: wmResult.watermarkToken,
        renderedText: wmResult.renderedText,
        outputSha256Hash: wmResult.outputSha256Hash,
        generatedAt: now,
      });

      await audit.record(
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

  let totalPages = 1;
  try {
    const parsedDoc = await PDFDocument.load(finalPdfBuffer, { ignoreEncryption: true });
    totalPages = Math.max(1, parsedDoc.getPageCount());
  } catch {
    totalPages = 1;
  }

  if (pageNumber !== undefined) {
    finalPdfBuffer = await watermarkEngine.extractPdfPage(finalPdfBuffer, pageNumber);
    outputSha256Hash = crypto.createHash('sha256').update(finalPdfBuffer).digest('hex');
  }

  await audit.record(
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
    totalPages,
  };
}
