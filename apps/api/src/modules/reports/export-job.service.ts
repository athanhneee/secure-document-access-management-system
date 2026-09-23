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
        },
      });
    }

    // Process asynchronously (or immediate sync in background)
    void this.processExportJob(id, input, actor);

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
    if (!buffer && job.file_path && fs.existsSync(job.file_path)) {
      buffer = fs.readFileSync(job.file_path);
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

    const ext = job.format.toLowerCase();
    const filename = `${job.export_type.toLowerCase()}-${job.id.slice(0, 8)}.${ext === 'excel' ? 'csv' : ext}`;

    return {
      buffer,
      mimeType: job.mime_type ?? 'application/octet-stream',
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
  ): Promise<void> {
    try {
      await this.database.asyncExportJob.update({
        where: { id: jobId },
        data: { status: 'PROCESSING' },
      });

      let contentBuffer: Buffer;
      let mimeType = 'text/plain';
      let rowCount = 0;

      switch (input.exportType) {
        case 'AUDIT_LOGS': {
          const logs = await this.database.auditLog.findMany({
            take: 1000,
            orderBy: { occurred_at: 'desc' },
          });
          rowCount = logs.length;

          if (input.format === 'JSON') {
            mimeType = 'application/json';
            contentBuffer = Buffer.from(JSON.stringify(logs, null, 2), 'utf-8');
          } else {
            // CSV / EXCEL with Formula Injection Sanitization!
            mimeType = 'text/csv; charset=utf-8';
            const rows = logs.map((l) => ({
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
            const columns = [
              { key: 'id' as const, header: 'Log ID' },
              { key: 'occurred_at' as const, header: 'Timestamp (UTC)' },
              { key: 'actor_username' as const, header: 'Actor' },
              { key: 'action' as const, header: 'Action' },
              { key: 'object_type' as const, header: 'Resource Type' },
              { key: 'object_id' as const, header: 'Resource ID' },
              { key: 'outcome' as const, header: 'Outcome' },
              { key: 'ip_address' as const, header: 'IP Address' },
              { key: 'chain_partition' as const, header: 'Partition' },
              { key: 'chain_sequence' as const, header: 'Sequence' },
              { key: 'entry_hash' as const, header: 'HMAC Hash' },
            ];
            const csvData = generateCsv(rows, columns);
            // Prefix UTF-8 BOM if Excel requested
            const prefix = input.format === 'EXCEL' ? '\uFEFF' : '';
            contentBuffer = Buffer.from(prefix + csvData, 'utf-8');
          }
          break;
        }

        case 'SECURITY_ALERTS': {
          const alerts = await this.database.securityAlert.findMany({
            take: 1000,
            orderBy: { detected_at: 'desc' },
          });
          rowCount = alerts.length;

          if (input.format === 'JSON') {
            mimeType = 'application/json';
            contentBuffer = Buffer.from(JSON.stringify(alerts, null, 2), 'utf-8');
          } else {
            mimeType = 'text/csv; charset=utf-8';
            const rows = alerts.map((a) => ({
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
            const columns = [
              { key: 'id' as const, header: 'Alert ID' },
              { key: 'alert_type' as const, header: 'Alert Type' },
              { key: 'severity' as const, header: 'Severity' },
              { key: 'status' as const, header: 'Status' },
              { key: 'title' as const, header: 'Title' },
              { key: 'description' as const, header: 'Description' },
              { key: 'detected_at' as const, header: 'Detected At (UTC)' },
              { key: 'resolved_at' as const, header: 'Resolved At' },
              { key: 'resolution_note' as const, header: 'Resolution Note' },
            ];
            const csvData = generateCsv(rows, columns);
            contentBuffer = Buffer.from(csvData, 'utf-8');
          }
          break;
        }

        case 'INCIDENT_REPORTS': {
          const incidents = await this.database.incidentReport.findMany({
            take: 1000,
            orderBy: { created_at: 'desc' },
          });
          rowCount = incidents.length;

          if (input.format === 'JSON') {
            mimeType = 'application/json';
            contentBuffer = Buffer.from(JSON.stringify(incidents, null, 2), 'utf-8');
          } else {
            mimeType = 'text/csv; charset=utf-8';
            const rows = incidents.map((i) => ({
              id: i.id,
              incident_code: i.incident_code,
              status: i.status,
              title: i.title,
              summary: i.summary,
              created_at: i.created_at.toISOString(),
              submitted_at: i.submitted_at?.toISOString() ?? '',
              closed_at: i.closed_at?.toISOString() ?? '',
            }));
            const columns = [
              { key: 'id' as const, header: 'ID' },
              { key: 'incident_code' as const, header: 'Incident Code' },
              { key: 'status' as const, header: 'Status' },
              { key: 'title' as const, header: 'Title' },
              { key: 'summary' as const, header: 'Summary' },
              { key: 'created_at' as const, header: 'Created At' },
              { key: 'submitted_at' as const, header: 'Submitted At' },
              { key: 'closed_at' as const, header: 'Closed At' },
            ];
            const csvData = generateCsv(rows, columns);
            contentBuffer = Buffer.from(csvData, 'utf-8');
          }
          break;
        }

        default: {
          // SYSTEM_REPORT
          const snapshots = await this.database.systemHealthSnapshot.findMany({
            take: 50,
            orderBy: { captured_at: 'desc' },
          });
          rowCount = snapshots.length;
          mimeType = 'application/json';
          contentBuffer = Buffer.from(JSON.stringify(snapshots, null, 2), 'utf-8');
          break;
        }
      }

      // Compute hash and size
      const sha256Hash = createHash('sha256').update(contentBuffer).digest('hex');
      const fileSizeBytes = BigInt(contentBuffer.length);

      // Store in memory
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
