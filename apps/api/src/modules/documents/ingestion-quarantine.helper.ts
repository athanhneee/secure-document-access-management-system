/**
 * Module: Quarantine Staging, Antivirus Scanning & Infected Evidence Helper
 * Algorithm: Stages spooled uploads into the private quarantine bucket, executes ClamAV scanning,
 *   and isolates infected samples in non-discoverable `DRAFT` (`discoverable = false`) forensic records.
 */
import { BadRequestException, ServiceUnavailableException, type Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
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
 * Algorithm: Quarantine Bucket Staging & ClamAV Malware Gate
 * Uploads spooled file to quarantine, scans with ClamAV, and retains infected objects for forensic inspection.
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
  try {
    const spoolBuffer = await fsp.readFile(spoolFilePath);
    await storage.putObject(
      storage.quarantineBucket,
      quarantineKey,
      spoolBuffer,
      validatedInfo.mimeType,
    );
    session.storageKeysToDelete.push({ bucket: storage.quarantineBucket, key: quarantineKey });
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordDocumentUpload(
        spoolBuffer.length,
        validatedInfo.extension,
      );
    } catch {
      // Optional metrics fallback
    }
  } catch (err: unknown) {
    await compensation.compensate(session);
    throw err;
  }

  const scanResult = await antivirus.scan(await fsp.readFile(spoolFilePath));
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
    // CONFLICT-RESOLVED: Khi ClamAV gặp sự cố kỹ thuật (FAILED), xóa đối tượng cách ly và ném 503 SERVICE_UNAVAILABLE thay vì gán nhãn sai thành INFECTED/MALWARE_DETECTED.
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
      departmentId: input.departmentId ?? 1n,
      title: input.title,
    });
    throw new BadRequestException({
      errorCode: AppErrorCode.MALWARE_DETECTED,
      message: `Malware detected in uploaded file: ${scanResult.virusName ?? 'Infected file'}. File has been quarantined.`,
    });
  }
}

/**
 * Algorithm: Isolated Quarantine Evidence Persistence
 * Records an `INFECTED` document version in non-discoverable `DRAFT` state (`discoverable = false`).
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
