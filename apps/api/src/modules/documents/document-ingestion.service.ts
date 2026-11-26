/**
 * Module: Zero-Trust Streaming Document Ingestion Pipeline Service
 * Thuật toán: Đường Ống Tiếp Nhận Tài Liệu Bù Trừ Saga Tiết Kiệm Bộ Nhớ & Dọn Dẹp Tệp Tạm Bắt Buộc Trong `finally`.
 *   1. Kiểm định điều kiện tiên quyết (SoD, thẩm quyền phòng ban, trần độ mật Bell-LaPadula) trước khi ghi đệm luồng tải lên ra thư mục tạm `sda-ing-*`.
 *   2. Quét cấu trúc ZIP/OOXML, đẩy lên kho cách ly và quét ClamAV trực tiếp qua `fs.createReadStream` để không giữ đồng thời 3 bản sao 50MB trong RAM.
 *   3. Xóa ngay tệp tạm bản rõ sau khi đọc vào bộ mã hóa phong bì AES-256-GCM, và đảm bảo thu dọn thư mục `sda-ing-*` trong khối `finally` trên mọi nhánh.
 */
import { Injectable, Logger, Optional, PayloadTooLargeException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RedlockService } from '../concurrency/redlock.service.js';
import { FileValidationService, type ValidatedFileInfo } from './file-validation.service.js';
import { ZipBombGuardService } from './zip-bomb-guard.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { AntivirusScannerService } from './antivirus-scanner.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentAuditService } from './document-audit.service.js';
import { OrphanCompensationService } from './orphan-compensation.service.js';
import {
  spoolUploadStreamToTempFile,
  validateIngestionPreconditions,
  type IngestDocumentInput,
  type IngestDocumentOutput,
} from './ingestion-validation.helper.js';
import { stageAndScanQuarantineUpload } from './ingestion-quarantine.helper.js';
import {
  persistCleanIngestedVersionWithStatus,
  type PersistedIngestedVersionResult,
} from './ingestion-version.helper.js';

export type { IngestDocumentInput, IngestDocumentOutput } from './ingestion-validation.helper.js';

@Injectable()
export class DocumentIngestionService {
  private readonly logger = new Logger(DocumentIngestionService.name);
  private readonly maxFileSize: number;
  private readonly database: ReturnType<typeof getDatabaseClient>;

  constructor(
    config: AppConfigService,
    private readonly fileValidation: FileValidationService,
    private readonly zipBombGuard: ZipBombGuardService,
    private readonly storage: ObjectStorageService,
    private readonly antivirus: AntivirusScannerService,
    private readonly encryption: DocumentEncryptionService,
    private readonly audit: DocumentAuditService,
    private readonly compensation: OrphanCompensationService,
    @Optional() databaseClient?: ReturnType<typeof getDatabaseClient> | undefined,
    @Optional() private readonly redlock?: RedlockService,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    this.maxFileSize = config.get('UPLOAD_MAX_FILE_SIZE_BYTES');
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as ReturnType<typeof getDatabaseClient>;
    }
  }

  get maxUploadFileSizeBytes(): number {
    return this.maxFileSize;
  }

  /**
   * Thuật toán: Đường ống tiếp nhận tài liệu đa chặng có bù trừ Saga và dọn tệp tạm `sda-ing-*` bắt buộc trong `finally`.
   */
  async ingestDocument(input: IngestDocumentInput): Promise<IngestDocumentOutput> {
    await validateIngestionPreconditions(input, this.database, this.authorization);

    const session = this.compensation.createSession();
    const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-ing-'));
    session.tempFilesToDelete.push(tempDir);
    const spoolFilePath = path.join(tempDir, `spool-${randomUUID()}.tmp`);
    session.tempFilesToDelete.push(spoolFilePath);

    try {
      const targetDocId = input.documentId ?? randomUUID();
      let validatedInfo: ValidatedFileInfo;
      try {
        validatedInfo = this.fileValidation.preValidate(input.rawFilename, input.declaredMime);
      } catch (err) {
        input.fileStream.destroy();
        await this.compensation.compensate(session);
        await this.audit.record(
          {
            action: 'DOCUMENT_UPLOAD_FAILED',
            outcome: 'FAILED',
            actorUserId: input.principal.userId,
            actorUsername: input.principal.username,
            documentId: targetDocId,
            reasonCode: AppErrorCode.INVALID_FILE_TYPE,
          },
          input.context,
        );
        throw err;
      }

      await this.audit.record(
        {
          action: 'DOCUMENT_UPLOAD_STARTED',
          outcome: 'SUCCESS',
          actorUserId: input.principal.userId,
          actorUsername: input.principal.username,
          documentId: targetDocId,
          details: {
            originalFilename: validatedInfo.sanitizedFilename,
            mimeType: validatedInfo.mimeType,
          },
        },
        input.context,
      );

      const failUpload = async (reasonCode: string): Promise<void> => {
        await this.compensation.compensate(session);
        await this.audit.record(
          {
            action: 'DOCUMENT_UPLOAD_FAILED',
            outcome: 'FAILED',
            actorUserId: input.principal.userId,
            actorUsername: input.principal.username,
            documentId: targetDocId,
            reasonCode,
          },
          input.context,
        );
      };

      let spoolResult: { totalBytes: number; sha256Hash: string; headerBuffer: Buffer };
      try {
        spoolResult = await spoolUploadStreamToTempFile(
          input.fileStream,
          spoolFilePath,
          this.maxFileSize,
        );
      } catch (err: unknown) {
        await failUpload(
          err instanceof PayloadTooLargeException
            ? AppErrorCode.FILE_SIZE_EXCEEDED
            : 'STREAM_ABORTED',
        );
        throw err;
      }

      try {
        this.fileValidation.validateMagicBytes(spoolResult.headerBuffer, validatedInfo.extension);
      } catch (err: unknown) {
        await failUpload(AppErrorCode.INVALID_FILE_TYPE);
        throw err;
      }

      if (validatedInfo.isOfficeFormat) {
        try {
          await this.zipBombGuard.inspectOfficeZip(spoolFilePath, validatedInfo.extension);
        } catch (err: unknown) {
          await failUpload(AppErrorCode.VALIDATION_FAILED);
          throw err;
        }
      }

      await stageAndScanQuarantineUpload({
        database: this.database,
        logger: this.logger,
        storage: this.storage,
        antivirus: this.antivirus,
        audit: this.audit,
        compensation: this.compensation,
        session,
        input,
        targetDocId,
        spoolFilePath,
        validatedInfo,
        totalBytes: spoolResult.totalBytes,
        sha256Hash: spoolResult.sha256Hash,
      });

      let dekReference = '';
      const documentStorageKey = `documents/${targetDocId}/${randomUUID()}.enc`;
      try {
        const plaintextBuffer = await fsp.readFile(spoolFilePath);
        await fsp.unlink(spoolFilePath).catch(() => {});
        const encryptedResult = await this.encryption.encryptBuffer(plaintextBuffer, targetDocId);
        plaintextBuffer.fill(0);
        dekReference = encryptedResult.dekReference;

        await this.storage.putObject(
          this.storage.documentsBucket,
          documentStorageKey,
          encryptedResult.encryptedBuffer,
          'application/octet-stream',
          undefined,
          encryptedResult.encryptedBuffer.byteLength,
        );
        session.storageKeysToDelete.push({
          bucket: this.storage.documentsBucket,
          key: documentStorageKey,
        });
      } catch (err: unknown) {
        await failUpload('ENCRYPTION_OR_STORAGE_FAILED');
        throw err;
      }

      let persisted: PersistedIngestedVersionResult = {
        versionNo: 1,
        documentStatus: 'DRAFT',
      };
      try {
        persisted = await persistCleanIngestedVersionWithStatus({
          database: this.database,
          redlock: this.redlock,
          authorization: this.authorization,
          input,
          targetDocId,
          validatedInfo,
          documentStorageKey,
          totalBytes: spoolResult.totalBytes,
          sha256Hash: spoolResult.sha256Hash,
          dekReference,
        });
      } catch (err: unknown) {
        await failUpload('DATABASE_TRANSACTION_FAILED');
        throw err;
      }
      const finalVersionNo = persisted.versionNo;

      session.storageKeysToDelete = session.storageKeysToDelete.filter(
        (item) => item.key !== documentStorageKey,
      );
      await this.compensation.compensate(session);

      await this.audit.record(
        {
          action: 'DOCUMENT_UPLOAD_COMPLETED',
          outcome: 'SUCCESS',
          actorUserId: input.principal.userId,
          actorUsername: input.principal.username,
          documentId: targetDocId,
          versionNo: finalVersionNo,
          details: {
            versionNo: finalVersionNo,
            originalFilename: validatedInfo.sanitizedFilename,
            mimeType: validatedInfo.mimeType,
            fileSizeBytes: spoolResult.totalBytes,
            sha256Hash: spoolResult.sha256Hash,
            scanStatus: 'CLEAN',
            documentStatus: persisted.documentStatus,
          },
        },
        input.context,
      );

      return {
        documentId: targetDocId,
        versionNo: finalVersionNo,
        originalFilename: validatedInfo.sanitizedFilename,
        mimeType: validatedInfo.mimeType,
        fileSizeBytes: spoolResult.totalBytes,
        sha256Hash: spoolResult.sha256Hash,
        scanStatus: 'CLEAN',
        status: persisted.documentStatus,
      };
    } finally {
      if (!input.fileStream.destroyed && !input.fileStream.readableEnded) {
        input.fileStream.destroy();
      }
      await fsp.unlink(spoolFilePath).catch(() => {});
      await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}
