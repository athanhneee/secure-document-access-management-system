/**
 * Module: Asynchronous Compliance Report Export Job Service
 * Thuật toán: Điều Phối Hàng Đợi Xuất Báo Cáo Tuân Thủ Bất Đồng Bộ Giữa `@sda/api` Và `@sda/worker` (`ExportJobService`).
 *   1. Kiểm định quyền RBAC theo miền dữ liệu (`AUDIT_LOGS`, `SECURITY_ALERTS`, `INCIDENT_REPORTS`, `SYSTEM_REPORT`) và ghi bao đóng phòng ban `__allowedDepartmentIds` vào `filter_params`.
 *   2. Trên `production`/`staging`/`development` mặc định (`EXPORT_EXECUTION_MODE = 'worker'`), giữ tác vụ `PENDING` trong PostgreSQL cho `@sda/worker`; trong kiểm thử đơn vị độc lập (`NODE_ENV = 'test'` hoặc `EXPORT_EXECUTION_MODE = 'inline'`), thực thi nền trực tiếp.
 *   3. Lưu và đọc trực tiếp tệp `.dat` mã hóa `AES-256-GCM` tại thư mục dùng chung `.local/exports` của gốc workspace (loại bỏ hoàn toàn `memoryStorage` trong RAM).
 */
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateExportJobInput } from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import {
  normalizeExportFilters,
  resolveExportAuthorizationScope,
} from './export-filter-scope.helper.js';
import {
  assertCrossUserExportScope,
  assertExportJobAccess,
  assertExportJobReadyForDownload,
  mapExportJobToDetail,
  readVerifiedExportArtifactAsync,
  resolveExportDownloadMeta,
  resolveWorkspaceExportDir,
  type ExportJobDetail,
} from './export-artifact.helper.js';
import {
  buildPersistedExportFilters,
  executeExportJobPipeline,
  executePendingExportJobById,
} from './export-job-runner.helper.js';

export type { ExportJobDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEFAULT_TTL_HOURS = 24;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

@Injectable()
export class ExportJobService {
  private readonly logger = new Logger(ExportJobService.name);
  private readonly database: PrismaClient;
  private readonly exportDir: string;
  private readonly isInjectedDatabaseClient: boolean;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    this.isInjectedDatabaseClient = Boolean(databaseClient);
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }

    // CONFLICT-RESOLVED: Đồng bộ đường dẫn `.local/exports` neo tại gốc workspace giữa `@sda/api` và `@sda/worker` (CRIT-08 / HIGH-1.3).
    this.exportDir = resolveWorkspaceExportDir();
    try {
      if (!fs.existsSync(this.exportDir)) {
        fs.mkdirSync(this.exportDir, { recursive: true, mode: 0o700 });
      }
    } catch {
      // Directory creation retried on artifact write if volume mounts lazily.
    }
  }

  private shouldExecuteInline(): boolean {
    const mode = process.env['EXPORT_EXECUTION_MODE']?.trim().toLowerCase();
    if (mode === 'inline') return true;
    if (mode === 'worker') return false;
    const nodeEnv = process.env['NODE_ENV']?.trim().toLowerCase();
    if (nodeEnv === 'production' || nodeEnv === 'staging') return false;
    return nodeEnv === 'test' || this.isInjectedDatabaseClient;
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
   * Thuật toán: Khởi tạo tác vụ xuất báo cáo bất đồng bộ TTL 24h, nhúng `__allowedDepartmentIds` vào `filter_params` và định tuyến thực thi theo `EXPORT_EXECUTION_MODE`.
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
    const persistedFilters = buildPersistedExportFilters(input.filterParams, allowedDepartmentIds);
    const job = await this.database.asyncExportJob.create({
      data: {
        id,
        requester_user_id: actor.userId,
        export_type: input.exportType,
        format: input.format,
        status: 'PENDING',
        filter_params: persistedFilters as never,
        expires_at: expiresAt,
      },
    });
    await this.recordAudit(actor, 'REPORT_EXPORT_REQUESTED', id, {
      exportType: input.exportType,
      format: input.format,
      expiresAt: expiresAt.toISOString(),
      correlationId: correlationId ?? null,
    });
    if (this.shouldExecuteInline()) {
      void this.processExportJob(id, input, actor, correlationId, allowedDepartmentIds).catch(
        (err) => this.logger.error(`Unhandled export job ${id} rejection:`, err),
      );
    }
    return mapExportJobToDetail(job);
  }

  /**
   * Thuật toán: Xử lý một tác vụ xuất đang ở trạng thái `PENDING` theo `jobId`, khôi phục phạm vi phòng ban `__allowedDepartmentIds` từ `filter_params`.
   */
  async processPendingJobById(jobId: string): Promise<void> {
    await executePendingExportJobById({
      database: this.database,
      authorization: this.authorization,
      exportDir: this.exportDir,
      logger: this.logger,
      jobId,
    });
  }

  /**
   * Thuật toán: Liệt kê 50 tác vụ xuất báo cáo gần nhất thuộc chính người dùng yêu cầu (`requester_user_id = actor.userId`).
   */
  async listExportJobs(actor: AuthPrincipal): Promise<{ data: ExportJobDetail[] }> {
    const jobs = await this.database.asyncExportJob.findMany({
      where: { requester_user_id: actor.userId },
      orderBy: { created_at: 'desc' },
      take: 50,
    });
    return { data: jobs.map(mapExportJobToDetail) };
  }

  private async loadAuthorizedJob(id: string, actor: AuthPrincipal) {
    if (!UUID_REGEX.test(id)) throw new BadRequestException('Export jobId must be a valid UUID.');
    const job = await this.database.asyncExportJob.findUnique({ where: { id } });
    if (!job) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: `Export job ${id} was not found.`,
      });
    }
    assertExportJobAccess(job, actor);
    await assertCrossUserExportScope(this.database, this.authorization, job, actor);
    return job;
  }

  /**
   * Thuật toán: Tra cứu chi tiết tác vụ xuất báo cáo kèm thẩm định UUID, quyền sở hữu và phạm vi phòng ban chéo.
   */
  async getExportJob(id: string, actor: AuthPrincipal): Promise<ExportJobDetail> {
    const job = await this.loadAuthorizedJob(id, actor);
    return mapExportJobToDetail(job);
  }

  /**
   * Thuật toán: Tải xuống tệp báo cáo có kiểm tra UUID, chống leo thang đường dẫn, xác thực phạm vi phòng ban, kiểm tra TTL và giải mã `AES-256-GCM`.
   */
  async downloadExportJob(
    id: string,
    actor: AuthPrincipal,
  ): Promise<{ buffer: Buffer; mimeType: string; filename: string }> {
    const job = await this.loadAuthorizedJob(id, actor);
    assertExportJobReadyForDownload(job);
    const buffer = await readVerifiedExportArtifactAsync(
      this.exportDir,
      id,
      job.file_path,
      this.logger,
      job.sha256_hash,
    );
    if (!buffer) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: 'Export file artifact is missing or expired from disk storage.',
      });
    }
    await this.recordAudit(actor, 'REPORT_EXPORT_DOWNLOADED', id, {
      exportType: job.export_type,
      format: job.format,
      fileSizeBytes: job.file_size_bytes?.toString() ?? null,
      sha256Hash: job.sha256_hash,
    });
    const { ext, mimeType } = resolveExportDownloadMeta(job.format, job.mime_type);
    return {
      buffer,
      mimeType: mimeType ?? 'application/octet-stream',
      filename: `${job.export_type.toLowerCase()}-${job.id.slice(0, 8)}.${ext}`,
    };
  }

  /**
   * Thuật toán: Kết xuất dữ liệu báo cáo theo phạm vi phòng ban, tính mã băm `SHA-256` và lưu tệp `.dat` mã hóa `AES-256-GCM` vào `.local/exports`.
   */
  async processExportJob(
    jobId: string,
    input: CreateExportJobInput,
    actor: AuthPrincipal,
    correlationId?: string,
    preResolvedDepartmentIds?: bigint[] | null,
  ): Promise<void> {
    const { database, authorization, exportDir, logger } = this;
    await executeExportJobPipeline({
      database,
      authorization,
      exportDir,
      logger,
      jobId,
      input,
      actor,
      correlationId,
      preResolvedDepartmentIds,
    });
  }
}
