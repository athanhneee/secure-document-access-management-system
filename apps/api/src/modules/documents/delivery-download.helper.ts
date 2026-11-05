/**
 * Module: Controlled Derivative Document Download Pipeline Helper
 * Algorithm: Enforces session + runtime `DOWNLOAD` grant + classification `allow_download`, decrypts to an
 *   ephemeral file cleaned in `finally`, and produces a watermarked PDF derivative whenever `requireWatermark` holds.
 */
import { ForbiddenException } from '@nestjs/common';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
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
 * Algorithm: Watermarked Derivative Download Pipeline
 */
export async function executeControlledDownload(params: {
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
    requireDownloadPolicy: true,
  });

  await grantsService.assertGrantValidForAccess(
    session.access_grant_id,
    principal.userId,
    'DOWNLOAD',
    now,
    documentId,
  );

  const docVersion = session.document_versions;
  const document = docVersion.document;
  const currentClassification = document.classification_history[0];

  if (!currentClassification?.classification_levels?.allow_download) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Document classification level does not allow downloads.',
    });
  }

  const requireWatermark = currentClassification?.classification_levels?.require_watermark ?? true;
  const encryptedBytes = await storage.getObject(storage.documentsBucket, docVersion.storage_key);
  const decrypted = await encryption.decryptToTempFile(
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
      const ext = docVersion.original_filename.split('.').pop()?.toLowerCase();
      let pdfForWatermark: Buffer = rawPlaintext;
      if (ext !== 'pdf') {
        pdfForWatermark = Buffer.from(
          await officeConverter.convertOfficeToPdf(rawPlaintext, docVersion.original_filename),
        );
      }

      const config = await watermarkEngine.getWatermarkConfig(
        currentClassification?.classification_level_id,
      );
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
    } else {
      fileBuffer = rawPlaintext;
    }
  } finally {
    await decrypted.cleanup();
  }

  const outputSha256Hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  await audit.record(
    {
      action: 'DOCUMENT_DOWNLOADED',
      outcome: 'SUCCESS',
      documentId,
      sessionId,
      details: { filename, sizeBytes: fileBuffer.length, outputSha256Hash },
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
