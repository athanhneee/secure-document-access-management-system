/**
 * Module: Zero-Trust Streaming Document Ingestion Pipeline Service
 * Algorithm: Saga-compensated multi-stage ingestion pipeline (precondition check -> backpressure temp spooling &
 *   SHA-256 -> magic bytes & ZipBomb/OOXML check -> quarantine ClamAV scan -> AES-256-GCM envelope encryption ->
 *   Redlock + `SELECT FOR UPDATE` version persistence -> orphan cleanup).
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
import { persistCleanIngestedVersion } from './ingestion-version.helper.js';

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

  /**
   * Algorithm: Saga-Compensated Zero-Trust Document Ingestion Pipeline
   */
  async ingestDocument(input: IngestDocumentInput): Promise<IngestDocumentOutput> {
    await validateIngestionPreconditions(input, this.database, this.authorization);

    const session = this.compensation.createSession();
    const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-upload-'));
    session.tempFilesToDelete.push(tempDir);

    const targetDocId = input.documentId ?? randomUUID();
    let validatedInfo: ValidatedFileInfo;
    try {
      validatedInfo = this.fileValidation.preValidate(input.rawFilename, input.declaredMime);
    } catch (err) {
      await this.compensation.compensate(session);
      throw err;
    }

    const spoolFilePath = path.join(tempDir, `spool-${randomUUID()}.tmp`);
    session.tempFilesToDelete.push(spoolFilePath);

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

    let encryptedResult: { encryptedBuffer: Buffer; dekReference: string };
    const documentStorageKey = `documents/${targetDocId}/${randomUUID()}.enc`;
    try {
      encryptedResult = await this.encryption.encryptBuffer(await fsp.readFile(spoolFilePath));
      await this.storage.putObject(
        this.storage.documentsBucket,
        documentStorageKey,
        encryptedResult.encryptedBuffer,
        'application/octet-stream',
      );
      session.storageKeysToDelete.push({
        bucket: this.storage.documentsBucket,
        key: documentStorageKey,
      });
    } catch (err: unknown) {
      await this.compensation.compensate(session);
      throw err;
    }

    let finalVersionNo = 1;
    try {
      finalVersionNo = await persistCleanIngestedVersion({
        database: this.database,
        redlock: this.redlock,
        authorization: this.authorization,
        input,
        targetDocId,
        validatedInfo,
        documentStorageKey,
        totalBytes: spoolResult.totalBytes,
        sha256Hash: spoolResult.sha256Hash,
        dekReference: encryptedResult.dekReference,
      });
    } catch (err: unknown) {
      await failUpload('DATABASE_TRANSACTION_FAILED');
      throw err;
    }

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
      status: 'DRAFT',
    };
  }
}
