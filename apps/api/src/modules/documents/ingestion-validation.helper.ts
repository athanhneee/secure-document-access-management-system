/**
 * Module: Document Ingestion Preconditions & Backpressure Stream Spooler
 * Algorithm: Enforces SoD role exclusions, UUID/`documentCode` syntax, existing document ownership/RBAC checks,
 *   and single-pass backpressure-controlled temp-file spooling (`0o600`) with incremental SHA-256 + 512-byte magic header capture.
 */
import { BadRequestException, ForbiddenException, PayloadTooLargeException } from '@nestjs/common';
import crypto from 'node:crypto';
import fs from 'node:fs';
import type { Readable } from 'node:stream';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES } from '../rbac/permission-matrix.js';
import { getUserClearanceRank } from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface IngestDocumentInput {
  fileStream: Readable;
  rawFilename: string;
  declaredMime: string;
  title?: string | undefined;
  departmentId?: bigint | undefined;
  documentCode?: string | undefined;
  documentId?: string | undefined;
  description?: string | undefined;
  classificationLevelId?: bigint | undefined;
  businessCategoryId?: bigint | undefined;
  retentionUntil?: string | undefined;
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

/**
 * Algorithm: Pre-Stream Ingestion Access & Identifier Guard
 * Destroys the upload stream immediately and rejects when SoD, identifier format, or version-upload permissions fail.
 */
export async function validateIngestionPreconditions(
  input: IngestDocumentInput,
  database: PrismaClient,
  authorization?: AuthorizationService,
): Promise<void> {
  const callerRoles = input.principal.roles ?? [];
  // CONFLICT-RESOLVED: Unconditionally block document ingestion by PRIVILEGED_SEPARATION_ROLES (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR).
  if (callerRoles.some((role) => PRIVILEGED_SEPARATION_ROLES.has(role))) {
    input.fileStream.destroy();
    throw new ForbiddenException({
      errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
      message:
        'Privileged administrative, security, and auditor accounts cannot upload business documents.',
    });
  }

  if (
    input.documentId !== undefined &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(input.documentId)
  ) {
    input.fileStream.destroy();
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Invalid documentId UUID format.',
    });
  }

  if (
    input.documentCode !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/u.test(input.documentCode)
  ) {
    input.fileStream.destroy();
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Invalid documentCode format.',
    });
  }

  if (input.documentId && typeof database?.document?.findUnique === 'function') {
    const targetDoc = await database.document.findUnique({
      where: { id: input.documentId },
      select: { id: true, owner_id: true, department_id: true, status: true },
    });
    if (targetDoc) {
      if (targetDoc.status === 'ARCHIVED' || targetDoc.status === 'DELETED') {
        input.fileStream.destroy();
        throw new BadRequestException({
          errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
          message: 'Cannot upload new version to an archived or deleted document.',
        });
      }
      if (targetDoc.owner_id !== input.principal.userId) {
        const canCreateVersion = authorization
          ? (await authorization.hasPermission(input.principal, 'DOCUMENT_VERSION', 'CREATE', {
              targetDepartmentId: targetDoc.department_id,
            })) ||
            (await authorization.hasPermission(input.principal, 'DOCUMENT', 'CLASSIFY', {
              targetDepartmentId: targetDoc.department_id,
            }))
          : false;
        if (!canCreateVersion) {
          input.fileStream.destroy();
          throw new ForbiddenException({
            errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
            message:
              'Only the document owner or authorized department administrator can upload a new version.',
          });
        }
      }
    }
  } else if (!input.documentId) {
    // CONFLICT-RESOLVED: Kiểm tra quyền trên phòng ban đích và độ mật Bell-LaPadula trước khi ghi đệm tệp tải lên mới (HIGH-05).
    let callerDeptId = (input.principal as { departmentId?: bigint }).departmentId;
    if (callerDeptId === undefined && typeof database?.user?.findUnique === 'function') {
      const caller = await database.user.findUnique({
        where: { id: input.principal.userId },
        select: { department_id: true },
      });
      callerDeptId = caller?.department_id ?? undefined;
    }
    const targetDeptId = input.departmentId ?? callerDeptId ?? 1n;
    if (typeof database?.department?.findUnique === 'function') {
      const dept = await database.department.findUnique({ where: { id: targetDeptId } });
      if (!dept || !dept.is_active) {
        input.fileStream.destroy();
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target department does not exist or is inactive.',
        });
      }
    }
    if (authorization && typeof authorization.hasPermission === 'function') {
      const scope = { targetDepartmentId: targetDeptId };
      const [canUpload, canClassify, canManage] = await Promise.all([
        authorization.hasPermission(input.principal, 'DOCUMENT', 'UPLOAD', scope),
        authorization.hasPermission(input.principal, 'DOCUMENT', 'CLASSIFY', scope),
        authorization.hasPermission(input.principal, 'DOCUMENT', 'MANAGE', scope),
      ]);
      if (!canUpload && !canClassify && !canManage) {
        input.fileStream.destroy();
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'Caller is not authorized to upload documents into the target department.',
        });
      }
    }
    if (
      input.classificationLevelId &&
      typeof database?.classificationLevel?.findUnique === 'function'
    ) {
      const level = await database.classificationLevel.findUnique({
        where: { id: input.classificationLevelId },
      });
      if (!level || !level.is_active) {
        input.fileStream.destroy();
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target classification level does not exist or is inactive.',
        });
      }
      if (typeof database?.userAttributeAssignment?.findFirst === 'function') {
        const rank = await getUserClearanceRank(database, input.principal.userId, new Date());
        if (rank < level.rank) {
          input.fileStream.destroy();
          throw new ForbiddenException({
            errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
            message: `Insufficient clearance level (${rank}) to upload document at rank ${level.rank}.`,
          });
        }
      }
    }
  }
}

/**
 * Algorithm: Backpressure-Controlled Single-Pass Temp Spooling & SHA-256 Hashing
 * Streams incoming bytes to a `0o600` temp file with `pause`/`drain` flow control, aborts immediately on `maxFileSize`
 * overflow, and computes incremental SHA-256 plus the leading 512-byte magic header in one pass.
 */
export async function spoolUploadStreamToTempFile(
  fileStream: Readable,
  spoolFilePath: string,
  maxFileSize: number,
): Promise<{ totalBytes: number; sha256Hash: string; headerBuffer: Buffer }> {
  let totalBytes = 0;
  const sha256Hasher = crypto.createHash('sha256');
  const headerChunks: Buffer[] = [];
  let headerBytes = 0;
  const writeStream = fs.createWriteStream(spoolFilePath, { mode: 0o600 });

  await new Promise<void>((resolve, reject) => {
    fileStream.on('data', (chunk: Buffer | Uint8Array) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;

      if (totalBytes > maxFileSize) {
        fileStream.destroy();
        writeStream.destroy();
        return reject(
          new PayloadTooLargeException({
            errorCode: AppErrorCode.FILE_SIZE_EXCEEDED,
            message: `File size exceeds allowed limit of ${maxFileSize} bytes.`,
          }),
        );
      }

      sha256Hasher.update(buf);
      if (headerBytes < 512) {
        headerChunks.push(buf);
        headerBytes += buf.length;
      }

      if (!writeStream.write(buf)) {
        fileStream.pause();
        writeStream.once('drain', () => fileStream.resume());
      }
    });

    fileStream.on('end', () => {
      writeStream.end(() => resolve());
    });
    fileStream.on('error', (err) => {
      writeStream.destroy();
      reject(err);
    });
    writeStream.on('error', (err) => {
      fileStream.destroy();
      reject(err);
    });
  });

  return {
    totalBytes,
    sha256Hash: sha256Hasher.digest('hex'),
    headerBuffer: Buffer.concat(headerChunks),
  };
}
