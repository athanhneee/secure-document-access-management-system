import {
  BadRequestException,
  Injectable,
  Logger,
  Optional,
  PayloadTooLargeException,
} from '@nestjs/common';
import crypto, { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Readable } from 'node:stream';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { FileValidationService, type ValidatedFileInfo } from './file-validation.service.js';
import { ZipBombGuardService } from './zip-bomb-guard.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { AntivirusScannerService } from './antivirus-scanner.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentAuditService } from './document-audit.service.js';
import { OrphanCompensationService } from './orphan-compensation.service.js';

export interface IngestDocumentInput {
  fileStream: Readable;
  rawFilename: string;
  declaredMime: string;
  title?: string | undefined;
  departmentId?: bigint | undefined;
  documentCode?: string | undefined;
  documentId?: string | undefined;
  changeNote?: string | undefined;
  principal: AuthPrincipal;
  context: RequestContext;
}

export interface IngestDocumentOutput {
  documentId: string;
  versionNo: number;
  originalFilename: string;
  mimeType: string;
  fileSizeBytes: number;
  sha256Hash: string;
  scanStatus: 'CLEAN' | 'INFECTED' | 'FAILED';
  status: 'DRAFT';
}

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
  ) {
    this.maxFileSize = config.get('UPLOAD_MAX_FILE_SIZE_BYTES');
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as ReturnType<typeof getDatabaseClient>;
    }
  }

  /**
   * Main zero-trust ingestion entrypoint.
   * Performs streaming reception, SHA-256 calculation, magic bytes validation,
   * zip-bomb protection, ClamAV quarantine scanning, AES-256-GCM envelope encryption,
   * database transaction metadata persistence, and compensation rollback if aborted.
   */
  async ingestDocument(input: IngestDocumentInput): Promise<IngestDocumentOutput> {
    const session = this.compensation.createSession();
    const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-upload-'));
    session.tempFilesToDelete.push(tempDir);

    const targetDocId = input.documentId ?? randomUUID();
    let validatedInfo: ValidatedFileInfo;

    try {
      // 1. Pre-validation of filename, extension, and declared MIME
      validatedInfo = this.fileValidation.preValidate(input.rawFilename, input.declaredMime);
    } catch (err) {
      await this.compensation.compensate(session);
      throw err;
    }

    const spoolFilePath = path.join(tempDir, `spool-${randomUUID()}.tmp`);
    session.tempFilesToDelete.push(spoolFilePath);

    // 2. Audit: upload started
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

    let totalBytes = 0;
    const sha256Hasher = crypto.createHash('sha256');
    const headerChunks: Buffer[] = [];
    let headerBytes = 0;

    // 3. Stream file from client to temporary spool file on disk
    try {
      const writeStream = fs.createWriteStream(spoolFilePath, { mode: 0o600 });

      await new Promise<void>((resolve, reject) => {
        input.fileStream.on('data', (chunk: Buffer | Uint8Array) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += buf.length;

          // Check file size limit on stream
          if (totalBytes > this.maxFileSize) {
            input.fileStream.destroy();
            writeStream.destroy();
            return reject(
              new PayloadTooLargeException({
                errorCode: AppErrorCode.FILE_SIZE_EXCEEDED,
                message: `File size exceeds allowed limit of ${this.maxFileSize} bytes.`,
              }),
            );
          }

          sha256Hasher.update(buf);

          if (headerBytes < 512) {
            headerChunks.push(buf);
            headerBytes += buf.length;
          }

          if (!writeStream.write(buf)) {
            input.fileStream.pause();
            writeStream.once('drain', () => input.fileStream.resume());
          }
        });

        input.fileStream.on('end', () => {
          writeStream.end(() => resolve());
        });

        input.fileStream.on('error', (err) => {
          writeStream.destroy();
          reject(err);
        });

        writeStream.on('error', (err) => {
          input.fileStream.destroy();
          reject(err);
        });
      });
    } catch (err: unknown) {
      await this.compensation.compensate(session);
      await this.audit.record(
        {
          action: 'DOCUMENT_UPLOAD_FAILED',
          outcome: 'FAILED',
          actorUserId: input.principal.userId,
          actorUsername: input.principal.username,
          documentId: targetDocId,
          reasonCode:
            err instanceof PayloadTooLargeException
              ? AppErrorCode.FILE_SIZE_EXCEEDED
              : 'STREAM_ABORTED',
        },
        input.context,
      );
      throw err;
    }

    const sha256Hash = sha256Hasher.digest('hex');
    const headerBuffer = Buffer.concat(headerChunks);

    // 4. Magic bytes validation
    try {
      this.fileValidation.validateMagicBytes(headerBuffer, validatedInfo.extension);
    } catch (err: unknown) {
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

    // 5. Office OpenXML zip-bomb & structure inspection
    if (validatedInfo.isOfficeFormat) {
      try {
        await this.zipBombGuard.inspectOfficeZip(spoolFilePath, validatedInfo.extension);
      } catch (err: unknown) {
        await this.compensation.compensate(session);
        await this.audit.record(
          {
            action: 'DOCUMENT_UPLOAD_FAILED',
            outcome: 'FAILED',
            actorUserId: input.principal.userId,
            actorUsername: input.principal.username,
            documentId: targetDocId,
            reasonCode: AppErrorCode.VALIDATION_FAILED,
          },
          input.context,
        );
        throw err;
      }
    }

    // 6. Put file into private quarantine bucket
    const quarantineKey = `quarantine/${targetDocId}/${randomUUID()}${validatedInfo.extension}`;
    try {
      const spoolBuffer = await fsp.readFile(spoolFilePath);
      await this.storage.putObject(
        this.storage.quarantineBucket,
        quarantineKey,
        spoolBuffer,
        validatedInfo.mimeType,
      );
      session.storageKeysToDelete.push({
        bucket: this.storage.quarantineBucket,
        key: quarantineKey,
      });
    } catch (err: unknown) {
      await this.compensation.compensate(session);
      throw err;
    }

    // 7. Antivirus scan (ClamAV & EICAR test signature check)
    const scanResult = await this.antivirus.scan(await fsp.readFile(spoolFilePath));

    await this.audit.record(
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

    // 8. Handle INFECTED files: file is quarantined, document is NEVER active
    if (scanResult.status !== 'CLEAN') {
      // The file remains in quarantine bucket. We do NOT delete it so security can inspect.
      // Remove it from session compensation so it stays in quarantine bucket
      session.storageKeysToDelete = session.storageKeysToDelete.filter(
        (item) => item.key !== quarantineKey,
      );
      await this.compensation.compensate(session);

      await this.audit.record(
        {
          action: 'DOCUMENT_UPLOAD_FAILED',
          outcome: 'FAILED',
          actorUserId: input.principal.userId,
          actorUsername: input.principal.username,
          documentId: targetDocId,
          reasonCode: AppErrorCode.MALWARE_DETECTED,
          details: {
            virusName: scanResult.virusName ?? 'Malware-Detected',
            quarantineKey,
          },
        },
        input.context,
      );

      // Record infected document row in DRAFT status (NEVER ACTIVE)
      await this.recordInfectedVersion(
        targetDocId,
        validatedInfo.sanitizedFilename,
        quarantineKey,
        validatedInfo.mimeType,
        totalBytes,
        sha256Hash,
        input.principal.userId,
        input.departmentId ?? 1n,
        input.title,
      );

      throw new BadRequestException({
        errorCode: AppErrorCode.MALWARE_DETECTED,
        message: `Malware detected in uploaded file: ${scanResult.virusName ?? 'Infected file'}. File has been quarantined.`,
      });
    }

    // 9. CLEAN file: Envelope encryption (AES-256-GCM + KMS wrapped DEK)
    let encryptedResult;
    try {
      const plaintextBuffer = await fsp.readFile(spoolFilePath);
      encryptedResult = await this.encryption.encryptBuffer(plaintextBuffer);
    } catch (err: unknown) {
      await this.compensation.compensate(session);
      throw err;
    }

    // 10. Store encrypted file in documents bucket (never overwrites old objects)
    const documentStorageKey = `documents/${targetDocId}/${randomUUID()}.enc`;
    try {
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

    // 11. Transaction: persist Document (status: DRAFT) and DocumentVersion (scan_status: CLEAN)
    let finalVersionNo = 1;
    try {
      const deptId = input.departmentId ?? 1n;
      const title = input.title ?? validatedInfo.sanitizedFilename;
      const docCode = input.documentCode ?? `DOC-${randomUUID().substring(0, 8).toUpperCase()}`;

      await this.database.$transaction(async (tx) => {
        // Concurrency control: Lock document row FOR UPDATE in PostgreSQL
        if (
          typeof (tx as unknown as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function'
        ) {
          await (
            tx as unknown as {
              $executeRawUnsafe: (sql: string, ...args: unknown[]) => Promise<unknown>;
            }
          ).$executeRawUnsafe(
            'SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE',
            targetDocId,
          );
        }

        // Check if document already exists
        const existingDoc = await tx.document.findUnique({
          where: { id: targetDocId },
          include: { versions: { select: { version_no: true } } },
        });

        if (
          existingDoc &&
          (existingDoc.status === 'ARCHIVED' || existingDoc.status === 'DELETED')
        ) {
          throw new BadRequestException({
            errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
            message: 'Cannot upload new version to an archived or deleted document.',
          });
        }

        if (!existingDoc) {
          // New document created in DRAFT status (Prompt 09 will handle ACTIVE transition)
          await tx.document.create({
            data: {
              id: targetDocId,
              document_code: docCode,
              title,
              owner_id: input.principal.userId,
              department_id: deptId,
              status: 'DRAFT',
              discoverable: true,
            },
          });
          finalVersionNo = 1;
        } else {
          // Increment version atomically
          const currentMaxVersion = existingDoc.versions.reduce(
            (max, v) => (v.version_no > max ? v.version_no : max),
            0,
          );
          finalVersionNo = currentMaxVersion + 1;
        }

        // Insert new document version
        await tx.documentVersion.create({
          data: {
            document_id: targetDocId,
            version_no: finalVersionNo,
            original_filename: validatedInfo.sanitizedFilename,
            storage_key: documentStorageKey,
            mime_type: validatedInfo.mimeType,
            file_size_bytes: BigInt(totalBytes),
            sha256_hash: sha256Hash,
            encryption_key_ref: encryptedResult.dekReference,
            scan_status: 'CLEAN',
            change_note: input.changeNote ?? 'Initial version',
            uploaded_by: input.principal.userId,
          },
        });
      });
    } catch (err: unknown) {
      // Transaction failed -> rollback storage objects via compensation
      await this.compensation.compensate(session);
      await this.audit.record(
        {
          action: 'DOCUMENT_UPLOAD_FAILED',
          outcome: 'FAILED',
          actorUserId: input.principal.userId,
          actorUsername: input.principal.username,
          documentId: targetDocId,
          reasonCode: 'DATABASE_TRANSACTION_FAILED',
        },
        input.context,
      );
      throw err;
    }

    // 12. Success: cleanup temporary spool files and quarantine copy
    // Remove documentStorageKey from compensation list so it is NOT deleted
    session.storageKeysToDelete = session.storageKeysToDelete.filter(
      (item) => item.key !== documentStorageKey,
    );
    await this.compensation.compensate(session);

    // 13. Audit upload completed
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
          fileSizeBytes: totalBytes,
          sha256Hash,
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
      fileSizeBytes: totalBytes,
      sha256Hash,
      scanStatus: 'CLEAN',
      status: 'DRAFT',
    };
  }

  private async recordInfectedVersion(
    documentId: string,
    filename: string,
    quarantineKey: string,
    mimeType: string,
    fileSizeBytes: number,
    sha256Hash: string,
    userId: bigint,
    departmentId: bigint,
    title?: string,
  ): Promise<void> {
    try {
      await this.database.$transaction(async (tx) => {
        const existing = await tx.document.findUnique({ where: { id: documentId } });
        if (!existing) {
          await tx.document.create({
            data: {
              id: documentId,
              document_code: `INF-${randomUUID().substring(0, 8).toUpperCase()}`,
              title: title ?? filename,
              owner_id: userId,
              department_id: departmentId,
              status: 'DRAFT', // NEVER ACTIVE
              discoverable: false,
            },
          });
        }

        await tx.documentVersion.create({
          data: {
            document_id: documentId,
            version_no: 1,
            original_filename: filename,
            storage_key: quarantineKey,
            mime_type: mimeType,
            file_size_bytes: BigInt(fileSizeBytes),
            sha256_hash: sha256Hash,
            encryption_key_ref: 'quarantine-unencrypted',
            scan_status: 'INFECTED',
            change_note: 'Quarantined infected upload',
            uploaded_by: userId,
          },
        });
      });
    } catch (err) {
      this.logger.error(`Failed to record infected document version in database: ${String(err)}`);
    }
  }
}
