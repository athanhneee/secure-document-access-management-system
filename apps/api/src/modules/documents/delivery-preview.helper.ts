/**
 * Module: Watermarked PDF Preview Pipeline Helper
 * Thuật toán: Đường Ống Xem Trước PDF Watermark Theo Phiên Có Bộ Đệm Dẫn Xuất Mã Hóa (`executeWatermarkedPreview`).
 *   1. Xác thực phiên hoạt động (`VIEW`), quyền cấp phát còn hạn và cập nhật `last_activity_at`.
 *   2. Kiểm tra bộ đệm dẫn xuất mã hóa trên `STORAGE_BUCKET_DERIVATIVES`:
 *      - Khi trúng cache (trang 2, 3, 4...): giải mã trực tiếp bản PDF đã watermark của phiên (0 lệnh KMS nguồn, 0 chuyển đổi Gotenberg, 0 đóng lại watermark/QR, chỉ 1 lần `PDFDocument.load` trích trang).
 *      - Khi trượt cache (trang 1 hoặc lần đầu): giải mã nguồn 1 lần (dọn tệp tạm trong `finally`), chuyển đổi Office qua Gotenberg 1 lần, đóng watermark 1 lần (lấy trực tiếp `wmResult.pageCount` không nạp lại PDF lần 2), lưu bản mã hóa vào `STORAGE_BUCKET_DERIVATIVES` và trích trang yêu cầu.
 */
import { BadRequestException } from '@nestjs/common';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import { PDFDocument } from 'pdf-lib';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
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
import { storeCachedSessionPdf, tryLoadCachedSessionPdf } from './derivative-pdf-cache.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const sessionWatermarkLocks = new Map<string, Promise<void>>();

/**
 * Thuật toán: Khóa tuần tự theo khóa `(sessionId, documentVersionId)` chống tranh chấp sinh trùng `watermark_token`
 * khi nhiều yêu cầu trang song song (ví dụ trang 1 + trang 2) cùng trượt bộ đệm lạnh (`MED-07`).
 */
export async function withSessionWatermarkLock<T>(
  sessionId: string,
  documentVersionId: bigint,
  work: () => Promise<T>,
): Promise<T> {
  const lockKey = `${sessionId}:${documentVersionId.toString()}`;
  const previous = sessionWatermarkLocks.get(lockKey) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = previous.then(() => current);
  sessionWatermarkLocks.set(lockKey, chained);

  await previous;
  try {
    return await work();
  } finally {
    release();
    if (sessionWatermarkLocks.get(lockKey) === chained) {
      sessionWatermarkLocks.delete(lockKey);
    }
  }
}

function isUniqueViolationError(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === 'P2002' || code === '23505';
}

/**
 * Thuật toán: Xử Lý Kết Xuất Xem Trước Tài Liệu & Trích Xuất Trang Watermark Tối Ưu Qua Bộ Đệm Phiên (`executeWatermarkedPreview`)
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
  stateStore?: DistributedStateService | undefined;
  config?: AppConfigService | undefined;
  documentId: string;
  sessionId: string;
  pageNumber: number | undefined;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<DeliveryFileResult> {
  const { database, pep, storage, encryption, officeConverter, watermarkEngine, grantsService } =
    params;
  const { audit, stateStore, config, documentId, sessionId, pageNumber, principal, context } =
    params;
  const now = new Date();
  const { session, sessionPolicy } = await loadValidatedDeliverySession({
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
  const classRequireWatermark =
    currentClassification?.classification_levels?.require_watermark ?? true;
  const requireWatermark = classRequireWatermark || Boolean(sessionPolicy?.watermarkRequired);
  const classificationContext = {
    classificationLevelId: currentClassification?.classification_level_id?.toString() ?? null,
    classificationName: currentClassification?.classification_levels?.name ?? null,
    requireWatermark,
    documentCode: document.document_code ?? null,
  };

  let finalPdfBuffer: Buffer;
  let watermarkToken: string | undefined;
  let outputSha256Hash: string;
  let totalPages = 1;

  const rawCachedSessionPdf = await tryLoadCachedSessionPdf({
    storage,
    stateStore,
    config,
    accessSessionId: sessionId,
    documentVersionId: docVersion.id,
    expectedContext: classificationContext,
  });
  const cachedSessionPdf =
    rawCachedSessionPdf && (!requireWatermark || Boolean(rawCachedSessionPdf.watermarkToken))
      ? rawCachedSessionPdf
      : null;

  if (cachedSessionPdf) {
    finalPdfBuffer = cachedSessionPdf.pdfBuffer;
    totalPages = cachedSessionPdf.pageCount;
    watermarkToken = cachedSessionPdf.watermarkToken;
    outputSha256Hash = cachedSessionPdf.outputSha256Hash;
  } else {
    const generated = await withSessionWatermarkLock(sessionId, docVersion.id, async () => {
      const recheckedRaw = await tryLoadCachedSessionPdf({
        storage,
        stateStore,
        config,
        accessSessionId: sessionId,
        documentVersionId: docVersion.id,
        expectedContext: classificationContext,
      });
      const recheckedCached =
        recheckedRaw && (!requireWatermark || Boolean(recheckedRaw.watermarkToken))
          ? recheckedRaw
          : null;
      if (recheckedCached) {
        return {
          pdfBuffer: recheckedCached.pdfBuffer,
          totalPages: recheckedCached.pageCount,
          watermarkToken: recheckedCached.watermarkToken,
          outputSha256Hash: recheckedCached.outputSha256Hash,
          cacheHitAfterLock: true,
        };
      }

      const encryptedBytes = await storage.getObject(
        storage.documentsBucket,
        docVersion.storage_key,
      );
      const decrypted = await encryption.decryptToTempFile(
        encryptedBytes,
        docVersion.encryption_key_ref,
        document.id,
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

      let builtPdfBuffer = pdfBuffer;
      let builtSha256Hash = crypto.createHash('sha256').update(builtPdfBuffer).digest('hex');
      let builtWatermarkToken: string | undefined;
      let builtTotalPages = 1;

      if (requireWatermark) {
        const wmConfig = await watermarkEngine.getWatermarkConfig(
          currentClassification?.classification_level_id,
        );
        const existingInstance = await database.watermarkInstance.findFirst({
          where: { access_session_id: sessionId, document_version_id: docVersion.id },
          orderBy: { generated_at: 'desc' },
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
          classificationCode: currentClassification?.classification_levels?.code,
          classificationRank: currentClassification?.classification_levels?.rank,
          requireWatermark: true,
        };
        let wmResult = await watermarkEngine.applyWatermarkToPdf(
          pdfBuffer,
          userData,
          docData,
          wmConfig,
          existingInstance?.watermark_token,
          now,
        );

        if (!existingInstance) {
          try {
            await watermarkEngine.recordWatermarkInstance({
              watermarkConfigId: wmConfig.id,
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
          } catch (err: unknown) {
            if (!isUniqueViolationError(err)) throw err;
            const winner = await database.watermarkInstance.findFirst({
              where: { access_session_id: sessionId, document_version_id: docVersion.id },
              orderBy: { generated_at: 'desc' },
            });
            if (!winner) throw err;
            wmResult = await watermarkEngine.applyWatermarkToPdf(
              pdfBuffer,
              userData,
              docData,
              wmConfig,
              winner.watermark_token,
              now,
            );
          }
        } else if (
          existingInstance.output_sha256_hash !== wmResult.outputSha256Hash ||
          existingInstance.rendered_text !== wmResult.renderedText.slice(0, 1000) ||
          existingInstance.watermark_config_id !== wmConfig.id
        ) {
          // BUG-053: Cập nhật nguyên chỗ `watermark_instances` (giữ nguyên `watermark_token` của phiên tránh đụng unique constraint `(access_session_id, document_version_id)`).
          if (typeof database.watermarkInstance?.update === 'function') {
            await database.watermarkInstance.update({
              where: { id: existingInstance.id },
              data: {
                watermark_config_id: wmConfig.id,
                rendered_text: wmResult.renderedText.slice(0, 1000),
                output_sha256_hash: wmResult.outputSha256Hash,
                generated_at: now,
              },
            });
          }
        }

        builtPdfBuffer = wmResult.watermarkedBuffer;
        builtWatermarkToken = wmResult.watermarkToken;
        builtSha256Hash = wmResult.outputSha256Hash;
        builtTotalPages = Math.max(1, wmResult.pageCount);
      } else {
        try {
          const parsedDoc = await PDFDocument.load(builtPdfBuffer, { ignoreEncryption: true });
          builtTotalPages = Math.max(1, parsedDoc.getPageCount());
        } catch {
          builtTotalPages = 1;
        }
      }

      await storeCachedSessionPdf({
        storage,
        stateStore,
        config,
        accessSessionId: sessionId,
        documentVersionId: docVersion.id,
        pdfBuffer: builtPdfBuffer,
        pageCount: builtTotalPages,
        watermarkToken: builtWatermarkToken,
        outputSha256Hash: builtSha256Hash,
        classificationContext,
      });

      return {
        pdfBuffer: builtPdfBuffer,
        totalPages: builtTotalPages,
        watermarkToken: builtWatermarkToken,
        outputSha256Hash: builtSha256Hash,
        cacheHitAfterLock: false,
      };
    });

    finalPdfBuffer = generated.pdfBuffer;
    totalPages = generated.totalPages;
    watermarkToken = generated.watermarkToken;
    outputSha256Hash = generated.outputSha256Hash;
  }

  if (pageNumber !== undefined) {
    finalPdfBuffer = await watermarkEngine.extractPdfPage(
      finalPdfBuffer,
      pageNumber,
      watermarkToken,
    );
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
        cacheHit: Boolean(cachedSessionPdf),
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
