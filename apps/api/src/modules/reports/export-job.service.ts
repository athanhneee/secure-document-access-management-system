import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  Logger,
  Optional,
} from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateExportJobInput,
  type ExportFormat,
  type ExportType,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { generateCsv } from './csv-formula-sanitizer.js';
import { generatePdfTable, generateExcelTable, type ExportColumn } from './export-formatter.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExportJobDetail {
  id: string;
  requesterUserId: string;
  exportType: ExportType;
  format: ExportFormat;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'EXPIRED';
  fileSizeBytes: string | null;
  sha256Hash: string | null;
  mimeType: string | null;
  rowCount: number;
  errorMessage: string | null;
  createdAt: string;
  completedAt: string | null;
  expiresAt: string;
  isExpired: boolean;
}

const DEFAULT_TTL_HOURS = 24;

@Injectable()
export class ExportJobService {
  private readonly logger = new Logger(ExportJobService.name);
  private readonly database: PrismaClient;
  private readonly exportDir: string;
  private readonly memoryStorage = new Map<string, Buffer>();

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }

    this.exportDir = path.join(process.cwd(), '.local', 'exports');
    try {
      if (!fs.existsSync(this.exportDir)) {
        fs.mkdirSync(this.exportDir, { recursive: true });
      }
    } catch {
      // Ignore if filesystem is restricted; memory storage will be used
    }
  }

  /**
   * Creates an asynchronous export job with 24h TTL.
   */
  async createExportJob(
    input: CreateExportJobInput,
    actor: AuthPrincipal,
    correlationId?: string,
  ): Promise<ExportJobDetail> {
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

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'REPORT_EXPORT_REQUESTED',
        objectType: 'ASYNC_EXPORT_JOB',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'AUDIT',
        details: {
          exportType: input.exportType,
          format: input.format,
          expiresAt: expiresAt.toISOString(),
          correlationId: correlationId ?? null,
        },
      });
    }

    // Process asynchronously with propagated correlation ID
    void this.processExportJob(id, input, actor, correlationId);

    return this.mapToDetail(job);
  }

  /**
   * Retrieves export job metadata and status.
   */
  async getExportJob(id: string, actor: AuthPrincipal): Promise<ExportJobDetail> {
    const job = await this.database.asyncExportJob.findUnique({
      where: { id },
    });

    if (!job) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: `Export job ${id} was not found.`,
      });
    }

    // Authorization: Requester or user with AUDIT_EXPORT / SYSTEM_REPORT_EXPORT
    this.assertAuthorizedToAccess(job, actor);

    return this.mapToDetail(job);
  }

  /**
   * Delivers the exported file stream with security headers.
   */
  async downloadExportJob(
    id: string,
    actor: AuthPrincipal,
  ): Promise<{
    buffer: Buffer;
    mimeType: string;
    filename: string;
  }> {
    const job = await this.database.asyncExportJob.findUnique({
      where: { id },
    });

    if (!job) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: `Export job ${id} was not found.`,
      });
    }

    this.assertAuthorizedToAccess(job, actor);

    // TTL check
    if (job.expires_at < new Date() || job.status === 'EXPIRED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.EXPORT_JOB_EXPIRED,
        message: 'This export job has expired. Please initiate a new export request.',
      });
    }

    if (job.status === 'PENDING' || job.status === 'PROCESSING') {
      throw new BadRequestException({
        errorCode: AppErrorCode.EXPORT_JOB_PENDING,
        message: 'Export job is still processing. Please try again shortly.',
      });
    }

    if (job.status === 'FAILED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INTERNAL_SERVER_ERROR,
        message: `Export job failed: ${job.error_message ?? 'Unknown error'}`,
      });
    }

    let buffer: Buffer | null = this.memoryStorage.get(id) ?? null;
    if (!buffer && job.file_path) {
      const resolvedBase = path.resolve(this.exportDir);
      const resolvedTarget = path.resolve(job.file_path);
      if (
        !resolvedTarget.startsWith(`${resolvedBase}${path.sep}`) &&
        resolvedTarget !== resolvedBase
      ) {
        this.logger.error(`Blocked out-of-bounds export file_path read for job ${id}`);
        throw new ForbiddenException({
          errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
          message: 'Export artifact path is invalid.',
        });
      }
      if (fs.existsSync(resolvedTarget) && !fs.lstatSync(resolvedTarget).isSymbolicLink()) {
        buffer = fs.readFileSync(resolvedTarget);
      }
    }

    if (!buffer) {
      throw new NotFoundException({
        errorCode: AppErrorCode.EXPORT_JOB_NOT_FOUND,
        message: 'Export file artifact is missing or expired from cache.',
      });
    }

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'REPORT_EXPORT_DOWNLOADED',
        objectType: 'ASYNC_EXPORT_JOB',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'AUDIT',
        details: {
          exportType: job.export_type,
          format: job.format,
          fileSizeBytes: job.file_size_bytes?.toString() ?? null,
          sha256Hash: job.sha256_hash,
        },
      });
    }

    const format = job.format.toUpperCase();
    let ext = 'csv';
    let mimeType = job.mime_type;

    if (format === 'EXCEL') {
      ext = 'xlsx';
      mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    } else if (format === 'PDF') {
      ext = 'pdf';
      mimeType = 'application/pdf';
    } else if (format === 'JSON') {
      ext = 'json';
      mimeType = 'application/json';
    } else {
      ext = 'csv';
      mimeType = 'text/csv; charset=utf-8';
    }

    const filename = `${job.export_type.toLowerCase()}-${job.id.slice(0, 8)}.${ext}`;

    return {
      buffer,
      mimeType: mimeType ?? 'application/octet-stream',
      filename,
    };
  }

  /**
   * Background processor for executing exports.
   */
  async processExportJob(
    jobId: string,
    input: CreateExportJobInput,
    _actor: AuthPrincipal,
    correlationId?: string,
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

      let contentBuffer: Buffer;
      let mimeType = 'text/plain';
      let rowCount = 0;

      let reportTitle = 'Audit Report';
      let rawRecords: unknown[] = [];
      let columns: ExportColumn[] = [];
      let rows: Record<string, string>[] = [];

      switch (input.exportType) {
        case 'AUDIT_LOGS': {
          reportTitle = 'Secure Document Access - Audit Trail Report';
          const logs = await this.database.auditLog.findMany({
            take: 1000,
            orderBy: { occurred_at: 'desc' },
          });
          rawRecords = logs;
          columns = [
            { key: 'id', header: 'Log ID' },
            { key: 'occurred_at', header: 'Timestamp (UTC)' },
            { key: 'actor_username', header: 'Actor' },
            { key: 'action', header: 'Action' },
            { key: 'object_type', header: 'Resource Type' },
            { key: 'object_id', header: 'Resource ID' },
            { key: 'outcome', header: 'Outcome' },
            { key: 'ip_address', header: 'IP Address' },
            { key: 'chain_partition', header: 'Partition' },
            { key: 'chain_sequence', header: 'Sequence' },
            { key: 'entry_hash', header: 'HMAC Hash' },
          ];
          rows = logs.map((l) => ({
            id: l.id.toString(),
            occurred_at: l.occurred_at.toISOString(),
            actor_username: l.actor_username ?? '',
            action: l.action,
            object_type: l.object_type,
            object_id: l.object_id ?? '',
            outcome: l.outcome,
            ip_address: l.ip_address ?? '',
            chain_partition: l.chain_partition,
            chain_sequence: l.chain_sequence.toString(),
            entry_hash: l.entry_hash,
          }));
          break;
        }

        case 'SECURITY_ALERTS': {
          reportTitle = 'Security Operations - Alert Incident Report';
          const alerts = await this.database.securityAlert.findMany({
            take: 1000,
            orderBy: { detected_at: 'desc' },
          });
          rawRecords = alerts;
          columns = [
            { key: 'id', header: 'Alert ID' },
            { key: 'alert_type', header: 'Alert Type' },
            { key: 'severity', header: 'Severity' },
            { key: 'status', header: 'Status' },
            { key: 'title', header: 'Title' },
            { key: 'description', header: 'Description' },
            { key: 'detected_at', header: 'Detected At (UTC)' },
            { key: 'resolved_at', header: 'Resolved At' },
            { key: 'resolution_note', header: 'Resolution Note' },
          ];
          rows = alerts.map((a) => ({
            id: a.id,
            alert_type: a.alert_type,
            severity: a.severity,
            status: a.status,
            title: a.title,
            description: a.description,
            detected_at: a.detected_at.toISOString(),
            resolved_at: a.resolved_at?.toISOString() ?? '',
            resolution_note: a.resolution_note ?? '',
          }));
          break;
        }

        case 'INCIDENT_REPORTS': {
          reportTitle = 'Security Operations - Incident Summary Report';
          const incidents = await this.database.incidentReport.findMany({
            take: 1000,
            orderBy: { created_at: 'desc' },
          });
          rawRecords = incidents;
          columns = [
            { key: 'id', header: 'ID' },
            { key: 'incident_code', header: 'Incident Code' },
            { key: 'status', header: 'Status' },
            { key: 'title', header: 'Title' },
            { key: 'summary', header: 'Summary' },
            { key: 'created_at', header: 'Created At' },
            { key: 'submitted_at', header: 'Submitted At' },
            { key: 'closed_at', header: 'Closed At' },
          ];
          rows = incidents.map((i) => ({
            id: i.id,
            incident_code: i.incident_code,
            status: i.status,
            title: i.title,
            summary: i.summary,
            created_at: i.created_at.toISOString(),
            submitted_at: i.submitted_at?.toISOString() ?? '',
            closed_at: i.closed_at?.toISOString() ?? '',
          }));
          break;
        }

        default: {
          reportTitle = 'System Health Diagnostic Snapshot Report';
          const snapshots = await this.database.systemHealthSnapshot.findMany({
            take: 50,
            orderBy: { captured_at: 'desc' },
          });
          rawRecords = snapshots;
          columns = [
            { key: 'id', header: 'ID' },
            { key: 'service_name', header: 'Service' },
            { key: 'status', header: 'Status' },
            { key: 'response_time_ms', header: 'Latency (ms)' },
            { key: 'error_count', header: 'Errors' },
            { key: 'captured_at', header: 'Captured At' },
          ];
          rows = snapshots.map((s) => ({
            id: s.id.toString(),
            service_name: s.service_name,
            status: s.status,
            response_time_ms: s.response_time_ms !== null ? s.response_time_ms.toString() : '0',
            error_count: s.error_count.toString(),
            captured_at: s.captured_at.toISOString(),
          }));
          break;
        }
      }

      rowCount = rows.length;

      if (input.format === 'JSON') {
        mimeType = 'application/json';
        contentBuffer = Buffer.from(
          JSON.stringify(
            rawRecords,
            (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
            2,
          ),
          'utf-8',
        );
      } else if (input.format === 'PDF') {
        mimeType = 'application/pdf';
        contentBuffer = await generatePdfTable(reportTitle, columns, rows);
      } else if (input.format === 'EXCEL') {
        mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        contentBuffer = await generateExcelTable(reportTitle, columns, rows);
      } else {
        // CSV with formula injection sanitization
        mimeType = 'text/csv; charset=utf-8';
        const csvData = generateCsv(rows, columns);
        contentBuffer = Buffer.from(csvData, 'utf-8');
      }

      // Compute hash and size
      const sha256Hash = createHash('sha256').update(contentBuffer).digest('hex');
      const fileSizeBytes = BigInt(contentBuffer.length);

      // Store in bounded in-memory cache (max 50 artifacts to prevent heap exhaustion)
      if (this.memoryStorage.size >= 50) {
        const oldestKey = this.memoryStorage.keys().next().value;
        if (oldestKey !== undefined) {
          this.memoryStorage.delete(oldestKey);
        }
      }
      this.memoryStorage.set(jobId, contentBuffer);

      // Store on disk if export directory is available
      let filePath: string | null = null;
      try {
        filePath = path.join(this.exportDir, `${jobId}.dat`);
        fs.writeFileSync(filePath, contentBuffer);
      } catch {
        filePath = null;
      }

      await this.database.asyncExportJob.update({
        where: { id: jobId },
        data: {
          status: 'COMPLETED',
          completed_at: new Date(),
          file_path: filePath,
          file_size_bytes: fileSizeBytes,
          sha256_hash: sha256Hash,
          mime_type: mimeType,
          row_count: rowCount,
        },
      });

      this.logger.log(
        `Export job ${jobId} completed successfully (${fileSizeBytes} bytes, ${rowCount} rows).`,
      );
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

  private assertAuthorizedToAccess(
    job: { requester_user_id: bigint; export_type: string },
    actor: AuthPrincipal,
  ): void {
    // Requester always has access
    if (job.requester_user_id === actor.userId) {
      return;
    }

    // Otherwise, check for AUDIT_EXPORT or SYSTEM_REPORT_EXPORT permission
    const roles = actor.roles ?? [];
    if (roles.includes('AUDITOR') || roles.includes('SECURITY_OFFICER')) {
      return;
    }

    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'You are not authorized to access or download this export job.',
    });
  }

  private mapToDetail(job: {
    id: string;
    requester_user_id: bigint;
    export_type: string;
    format: string;
    status: string;
    file_size_bytes: bigint | null;
    sha256_hash: string | null;
    mime_type: string | null;
    row_count: number;
    error_message: string | null;
    created_at: Date;
    completed_at: Date | null;
    expires_at: Date;
  }): ExportJobDetail {
    const isExpired = job.expires_at < new Date() || job.status === 'EXPIRED';
    return {
      id: job.id,
      requesterUserId: job.requester_user_id.toString(),
      exportType: job.export_type as ExportType,
      format: job.format as ExportFormat,
      status: (isExpired ? 'EXPIRED' : job.status) as ExportJobDetail['status'],
      fileSizeBytes: job.file_size_bytes?.toString() ?? null,
      sha256Hash: job.sha256_hash,
      mimeType: job.mime_type,
      rowCount: job.row_count,
      errorMessage: job.error_message,
      createdAt: job.created_at.toISOString(),
      completedAt: job.completed_at?.toISOString() ?? null,
      expiresAt: job.expires_at.toISOString(),
      isExpired,
    };
  }
}
