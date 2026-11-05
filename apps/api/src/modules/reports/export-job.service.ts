/**
 * Module: Asynchronous Compliance Report Export Job Service
 * Algorithm: Enforces domain-specific RBAC export scopes & department-subtree filters, schedules 24h-TTL
 *   async export jobs, executes bounded-FIFO (50-item) artifact generation with SHA-256 integrity hashing,
 *   and serves downloads with path-traversal/symlink guards.
 */
import { Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateExportJobInput, type ExportType } from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { buildExportDataset } from './export-dataset.builder.js';
import {
  normalizeExportFilters,
  resolveExportAuthorizationScope,
} from './export-filter-scope.helper.js';
import {
  assertExportJobAccess,
  assertExportJobReadyForDownload,
  mapExportJobToDetail,
  persistBoundedExportArtifact,
  readVerifiedExportArtifact,
  renderExportBuffer,
  resolveExportDownloadMeta,
  type ExportJobDetail,
} from './export-artifact.helper.js';

export type { ExportJobDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEFAULT_TTL_HOURS = 24;

@Injectable()
export class ExportJobService {
  private readonly logger = new Logger(ExportJobService.name);
  private readonly database: PrismaClient;
  private readonly exportDir: string;
  // shortcut: 50 fallback export artifacts (~50 MB) when local fs is read-only, stream artifacts to S3/MinIO exports bucket in multi-node cluster
  private readonly memoryStorage = new Map<string, Buffer>();

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }

    this.exportDir = path.join(process.cwd(), '.local', 'exports');
    try {
      if (!fs.existsSync(this.exportDir)) fs.mkdirSync(this.exportDir, { recursive: true });
    } catch {
      // Fallback to memoryStorage when filesystem is restricted
    }
  }

  private async recordAudit(
    actor: AuthPrincipal,
    action: 'REPORT_EXPORT_REQUESTED' | 'REPORT_EXPORT_DOWNLOADED',
    objectId: string,
    details: Record<string, string | number | boolean | null>,
  ): Promise<void> {
    if (!this.auditWriter) return;
    await this.auditWriter.writeLog({
      actorUserId: actor.userId,
      actorUsername: actor.username,
      action,
      objectType: 'ASYNC_EXPORT_JOB',
      objectId,
      outcome: 'SUCCESS',
      chainPartition: 'AUDIT',
      details,
    });
  }

  /**
   * Algorithm: Scoped Asynchronous Export Job Initialization with 24h TTL & Upfront Filter Validation
   */
  async createExportJob(
    input: CreateExportJobInput,
    actor: AuthPrincipal,
    correlationId?: string,
  ): Promise<ExportJobDetail> {
    const allowedDepartmentIds = await resolveExportAuthorizationScope(
      this.authorization,
      actor,
      input.exportType,
    );
    normalizeExportFilters(input.filterParams, allowedDepartmentIds);

    const id = randomUUID();
    const expiresAt = new Date(Date.now() + DEFAULT_TTL_HOURS * 60 * 60 * 1000);

    const job = await this.database.asyncExportJob.create({
      data: {
        id,
        requester_user_id: actor.userId,
        export_type: input.exportType,
        format: input.format,
        status: 'PENDING',
        filter_params: (input.filterParams ?? {}) as never,
        expires_at: expiresAt,
      },
    });

    await this.recordAudit(actor, 'REPORT_EXPORT_REQUESTED', id, {
      exportType: input.exportType,
      format: input.format,
      expiresAt: expiresAt.toISOString(),
      correlationId: correlationId ?? null,
    });

    void this.processExportJob(id, input, actor, correlationId, allowedDepartmentIds);
    return mapExportJobToDetail(job);
  }

  async getExportJob(id: string, actor: AuthPrincipal): Promise<ExportJobDetail> {
    const job = await this.database.asyncExportJob.findUnique({ where: { id } });
    if (!job) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: `Export job ${id} was not found.`,
      });
    }
    assertExportJobAccess(job, actor);
    return mapExportJobToDetail(job);
  }

  /**
   * Algorithm: Path-Traversal-Hardened, RBAC-Verified & TTL-Gated Export Artifact Delivery
   */
  async downloadExportJob(
    id: string,
    actor: AuthPrincipal,
  ): Promise<{ buffer: Buffer; mimeType: string; filename: string }> {
    const job = await this.database.asyncExportJob.findUnique({ where: { id } });
    if (!job) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: `Export job ${id} was not found.`,
      });
    }

    assertExportJobAccess(job, actor);
    await resolveExportAuthorizationScope(this.authorization, actor, job.export_type as ExportType);
    assertExportJobReadyForDownload(job);

    const buffer = readVerifiedExportArtifact(
      this.exportDir,
      this.memoryStorage,
      id,
      job.file_path,
      this.logger,
    );
    if (!buffer) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: 'Export file artifact is missing or expired from cache.',
      });
    }

    await this.recordAudit(actor, 'REPORT_EXPORT_DOWNLOADED', id, {
      exportType: job.export_type,
      format: job.format,
      fileSizeBytes: job.file_size_bytes?.toString() ?? null,
      sha256Hash: job.sha256_hash,
    });

    const { ext, mimeType } = resolveExportDownloadMeta(job.format);
    return {
      buffer,
      mimeType: mimeType ?? 'application/octet-stream',
      filename: `${job.export_type.toLowerCase()}-${job.id.slice(0, 8)}.${ext}`,
    };
  }

  /**
   * Algorithm: Bounded-FIFO (50-Entry) Background Export Pipeline with Scoped Dataset & SHA-256 Digest
   */
  async processExportJob(
    jobId: string,
    input: CreateExportJobInput,
    actor: AuthPrincipal,
    correlationId?: string,
    preResolvedDepartmentIds?: bigint[] | null,
  ): Promise<void> {
    const activeCorrId = correlationId || 'worker-internal';
    this.logger.log(
      `[Worker][ExportJob: ${jobId}][CorrelationId: ${activeCorrId}] Processing export ${input.exportType} (${input.format})`,
    );

    try {
      await this.database.asyncExportJob.update({
        where: { id: jobId },
        data: { status: 'PROCESSING' },
      });

      const allowedDeptIds =
        preResolvedDepartmentIds !== undefined
          ? preResolvedDepartmentIds
          : await resolveExportAuthorizationScope(this.authorization, actor, input.exportType);
      const dataset = await buildExportDataset(
        this.database,
        input.exportType,
        input.filterParams,
        allowedDeptIds,
      );
      const { contentBuffer, mimeType } = await renderExportBuffer(input.format, dataset);
      const sha256Hash = createHash('sha256').update(contentBuffer).digest('hex');
      const fileSizeBytes = BigInt(contentBuffer.length);
      const filePath = persistBoundedExportArtifact(
        this.exportDir,
        this.memoryStorage,
        jobId,
        contentBuffer,
      );

      await this.database.asyncExportJob.update({
        where: { id: jobId },
        data: {
          status: 'COMPLETED',
          completed_at: new Date(),
          file_path: filePath,
          file_size_bytes: fileSizeBytes,
          sha256_hash: sha256Hash,
          mime_type: mimeType,
          row_count: dataset.rows.length,
        },
      });
    } catch (err) {
      this.logger.error(`Export job ${jobId} failed:`, err);
      await this.database.asyncExportJob.update({
        where: { id: jobId },
        data: {
          status: 'FAILED',
          error_message: err instanceof Error ? err.message : String(err),
        },
      });
    }
  }
}
