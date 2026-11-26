/**
 * Module: Controlled Derivative Document Download Pipeline Helper
 * Thuật toán: Đường Ống Tải Xuống Bản Phái Sinh Có Watermark Bắt Buộc & Dọn Dẹp Tệp Tạm Trong `finally`.
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
import { withSessionWatermarkLock } from './delivery-preview.helper.js';
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

  const { session, sessionPolicy } = await loadValidatedDeliverySession({
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

  const classRequireWatermark =
    currentClassification?.classification_levels?.require_watermark ?? true;
  const requireWatermark = classRequireWatermark || Boolean(sessionPolicy?.watermarkRequired);
  const encryptedBytes = await storage.getObject(storage.documentsBucket, docVersion.storage_key);
  const decrypted = await encryption.decryptToTempFile(
    encryptedBytes,
    docVersion.encryption_key_ref,
    document.id,
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
      const wmResult = await withSessionWatermarkLock(sessionId, docVersion.id, async () => {
        const existingInstance =
          typeof database.watermarkInstance?.findFirst === 'function'
            ? await database.watermarkInstance.findFirst({
                where: { access_session_id: sessionId, document_version_id: docVersion.id },
                orderBy: { generated_at: 'desc' },
              })
            : null;
        const docData: WatermarkDocumentData = {
          id: document.id,
          documentCode: document.document_code,
          title: document.title,
          classificationName: currentClassification?.classification_levels?.name,
          classificationCode: currentClassification?.classification_levels?.code,
          classificationRank: currentClassification?.classification_levels?.rank,
          requireWatermark: true,
        };

        let applied = await watermarkEngine.applyWatermarkToPdf(
          pdfForWatermark,
          userData,
          docData,
          config,
          existingInstance?.watermark_token,
          now,
        );

        if (!existingInstance) {
          try {
            await watermarkEngine.recordWatermarkInstance({
              watermarkConfigId: config.id,
              accessSessionId: sessionId,
              documentVersionId: docVersion.id,
              userId: principal.userId,
              watermarkToken: applied.watermarkToken,
              renderedText: applied.renderedText,
              outputSha256Hash: applied.outputSha256Hash,
              generatedAt: now,
            });
          } catch (err: unknown) {
            const code = (err as { code?: string } | null)?.code;
            if (code !== 'P2002' && code !== '23505') throw err;
            const winner =
              typeof database.watermarkInstance?.findFirst === 'function'
                ? await database.watermarkInstance.findFirst({
                    where: { access_session_id: sessionId, document_version_id: docVersion.id },
                    orderBy: { generated_at: 'desc' },
                  })
                : null;
            if (!winner) throw err;
            applied = await watermarkEngine.applyWatermarkToPdf(
              pdfForWatermark,
              userData,
              docData,
              config,
              winner.watermark_token,
              now,
            );
          }
        } else if (typeof database.watermarkInstance?.update === 'function') {
          await database.watermarkInstance.update({
            where: { id: existingInstance.id },
            data: {
              watermark_config_id: config.id,
              rendered_text: applied.renderedText.slice(0, 1000),
              output_sha256_hash: applied.outputSha256Hash,
              generated_at: now,
            },
          });
        }

        return applied;
      });

      fileBuffer = wmResult.watermarkedBuffer;
      mimeType = 'application/pdf';
      filename = `${document.document_code || 'doc'}-watermarked.pdf`;
      watermarkToken = wmResult.watermarkToken;

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

  // Thuật toán: Tự động chuyển phiên tải xuống sang trạng thái `ENDED` sau khi đã hoàn tất xuất tệp để không để lại phiên ảo trên SOC (V-10).
  if (typeof database?.accessSession?.updateMany === 'function') {
    await database.accessSession
      .updateMany({
        where: { id: sessionId, status: 'ACTIVE' },
        data: { status: 'ENDED', ended_at: now, last_activity_at: now },
      })
      .catch(() => undefined);
  } else if (typeof database?.accessSession?.update === 'function') {
    await database.accessSession
      .update({
        where: { id: sessionId },
        data: { status: 'ENDED', ended_at: now, last_activity_at: now },
      })
      .catch(() => undefined);
  }

  return {
    buffer: fileBuffer,
    mimeType,
    filename,
    fileSizeBytes: fileBuffer.length,
    outputSha256Hash,
    watermarkToken,
  };
}
