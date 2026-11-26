/**
 * Module: Quarantine Staging, Antivirus Scanning & Infected Evidence Helper
 * Thuật toán: Cô Lập Phân Vùng Cách Ly Bằng Luồng Đọc (`fs.createReadStream`) & Quét Mã Độc Không Giữ Đa Bản Sao Trong RAM.
 *   1. Truyền trực tiếp luồng đọc `fs.createReadStream(spoolFilePath)` lên bucket cách ly (`quarantine`) kèm `totalBytes`
 *      thay vì nạp nguyên tệp 50MB vào `Buffer` nhiều lần.
 *   2. Mở luồng đọc độc lập thứ hai truyền thẳng sang `AntivirusScannerService.scan` với cửa sổ trượt 68-byte EICAR và `zINSTREAM` backpressure.
 *   3. Nếu phát hiện mã độc (`INFECTED`), giữ lại đối tượng cách ly làm bằng chứng pháp y trong bản ghi `DRAFT` ẩn (`discoverable = false`).
 */
import { BadRequestException, ServiceUnavailableException, type Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AntivirusScannerService } from './antivirus-scanner.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import type { ValidatedFileInfo } from './file-validation.service.js';
import type { IngestDocumentInput } from './ingestion-validation.helper.js';
import type { ObjectStorageService } from './object-storage.service.js';
import type {
  OrphanCompensationService,
  UploadSessionCompensation,
} from './orphan-compensation.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Đẩy tệp tạm vào kho cách ly qua luồng đọc và quét ClamAV không nạp đồng thời nhiều bản sao 50MB vào RAM.
 */
export async function stageAndScanQuarantineUpload(params: {
  database: PrismaClient;
  logger: Logger;
  storage: ObjectStorageService;
  antivirus: AntivirusScannerService;
  audit: DocumentAuditService;
  compensation: OrphanCompensationService;
  session: UploadSessionCompensation;
  input: IngestDocumentInput;
  targetDocId: string;
  spoolFilePath: string;
  validatedInfo: ValidatedFileInfo;
  totalBytes: number;
  sha256Hash: string;
}): Promise<void> {
  const {
    database,
    logger,
    storage,
    antivirus,
    audit,
    compensation,
    session,
    input,
    targetDocId,
    spoolFilePath,
    validatedInfo,
    totalBytes,
    sha256Hash,
  } = params;

  const quarantineKey = `quarantine/${targetDocId}/${randomUUID()}${validatedInfo.extension}`;
  const quarantineStream = fs.createReadStream(spoolFilePath);
  quarantineStream.on('error', () => {});
  try {
    await storage.putObject(
      storage.quarantineBucket,
      quarantineKey,
      quarantineStream,
      validatedInfo.mimeType,
      undefined,
      totalBytes,
    );
    session.storageKeysToDelete.push({ bucket: storage.quarantineBucket, key: quarantineKey });
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordDocumentUpload(totalBytes, validatedInfo.extension);
    } catch {
      // Optional metrics fallback
    }
  } catch (err: unknown) {
    await compensation.compensate(session);
    await audit.record(
      {
        action: 'DOCUMENT_UPLOAD_FAILED',
        outcome: 'FAILED',
        actorUserId: input.principal.userId,
        actorUsername: input.principal.username,
        documentId: targetDocId,
        reasonCode: 'QUARANTINE_STORAGE_FAILED',
      },
      input.context,
    );
    throw err;
  } finally {
    quarantineStream.destroy();
  }

  const scanStream = fs.createReadStream(spoolFilePath);
  scanStream.on('error', () => {});
  let scanResult: Awaited<ReturnType<AntivirusScannerService['scan']>>;
  try {
    scanResult = await antivirus.scan(scanStream);
  } finally {
    scanStream.destroy();
  }
  await audit.record(
    {
      action: 'DOCUMENT_SCAN_RESULT',
      outcome: scanResult.status === 'CLEAN' ? 'SUCCESS' : 'FAILED',
      actorUserId: input.principal.userId,
      actorUsername: input.principal.username,
      documentId: targetDocId,
      details: {
        scanStatus: scanResult.status,
        virusName: scanResult.virusName ?? null,
        durationMs: scanResult.durationMs,
      },
    },
    input.context,
  );

  if (scanResult.status === 'FAILED') {
    await compensation.compensate(session);
    await audit.record(
      {
        action: 'DOCUMENT_UPLOAD_FAILED',
        outcome: 'FAILED',
        actorUserId: input.principal.userId,
        actorUsername: input.principal.username,
        documentId: targetDocId,
        reasonCode: AppErrorCode.SERVICE_UNAVAILABLE,
        details: { scanStatus: 'FAILED', durationMs: scanResult.durationMs },
      },
      input.context,
    );
    throw new ServiceUnavailableException({
      errorCode: AppErrorCode.SERVICE_UNAVAILABLE,
      message:
        'Antivirus scanning service is temporarily unavailable. Upload rejected fail-closed.',
    });
  }

  if (scanResult.status !== 'CLEAN') {
    session.storageKeysToDelete = session.storageKeysToDelete.filter(
      (item) => item.key !== quarantineKey,
    );
    await compensation.compensate(session);
    await audit.record(
      {
        action: 'DOCUMENT_UPLOAD_FAILED',
        outcome: 'FAILED',
        actorUserId: input.principal.userId,
        actorUsername: input.principal.username,
        documentId: targetDocId,
        reasonCode: AppErrorCode.MALWARE_DETECTED,
        details: { virusName: scanResult.virusName ?? 'Malware-Detected', quarantineKey },
      },
      input.context,
    );
    let resolvedQuarantineDeptId =
      input.departmentId ?? (input.principal as { departmentId?: bigint }).departmentId;
    if (
      resolvedQuarantineDeptId === undefined &&
      typeof database?.user?.findUnique === 'function'
    ) {
      const uploaderRow = await database.user
        .findUnique({ where: { id: input.principal.userId }, select: { department_id: true } })
        .catch(() => null);
      if (uploaderRow?.department_id != null) {
        resolvedQuarantineDeptId = uploaderRow.department_id;
      }
    }
    await recordQuarantinedInfectedVersion({
      database,
      logger,
      documentId: targetDocId,
      filename: validatedInfo.sanitizedFilename,
      quarantineKey,
      mimeType: validatedInfo.mimeType,
      fileSizeBytes: totalBytes,
      sha256Hash,
      userId: input.principal.userId,
      departmentId: resolvedQuarantineDeptId ?? 1n,
      title: input.title,
    });
    throw new BadRequestException({
      errorCode: AppErrorCode.MALWARE_DETECTED,
      message: `Malware detected in uploaded file: ${scanResult.virusName ?? 'Infected file'}. File has been quarantined.`,
    });
  }
}

/**
 * Thuật toán: Lưu vết bằng chứng pháp y phiên bản tệp nhiễm mã độc ở trạng thái `DRAFT` ẩn (`discoverable = false`).
 */
export async function recordQuarantinedInfectedVersion(params: {
  database: PrismaClient;
  logger: Logger;
  documentId: string;
  filename: string;
  quarantineKey: string;
  mimeType: string;
  fileSizeBytes: number;
  sha256Hash: string;
  userId: bigint;
  departmentId: bigint;
  title?: string | undefined;
}): Promise<void> {
  try {
    await params.database.$transaction(async (tx) => {
      const existing = await tx.document.findUnique({
        where: { id: params.documentId },
        include: { versions: { select: { version_no: true } } },
      });
      let nextInfectedVersionNo = 1;
      if (!existing) {
        await tx.document.create({
          data: {
            id: params.documentId,
            document_code: `INF-${randomUUID().substring(0, 8).toUpperCase()}`,
            title: params.title ?? params.filename,
            owner_id: params.userId,
            department_id: params.departmentId,
            status: 'DRAFT',
            discoverable: false,
          },
        });
      } else if (
        Array.isArray((existing as { versions?: Array<{ version_no: number }> }).versions)
      ) {
        const maxV = (existing as { versions: Array<{ version_no: number }> }).versions.reduce(
          (m, v) => (v.version_no > m ? v.version_no : m),
          0,
        );
        nextInfectedVersionNo = maxV + 1;
      }

      await tx.documentVersion.create({
        data: {
          document_id: params.documentId,
          version_no: nextInfectedVersionNo,
          original_filename: params.filename,
          storage_key: params.quarantineKey,
          mime_type: params.mimeType,
          file_size_bytes: BigInt(params.fileSizeBytes),
          sha256_hash: params.sha256Hash,
          encryption_key_ref: 'quarantine-unencrypted',
          scan_status: 'INFECTED',
          change_note: 'Quarantined infected upload',
          uploaded_by: params.userId,
        },
      });
    });
  } catch (err) {
    params.logger.error(`Failed to record infected document version in database: ${String(err)}`);
  }
}
