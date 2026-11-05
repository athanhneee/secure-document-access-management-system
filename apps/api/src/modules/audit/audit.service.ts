/**
 * @module AuditService
 * Algorithm: Role-Scoped Audit Log Querying (IDOR-Protected), Sanitized Export & Chain Verification Facade.
 */
import { ForbiddenException, Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import type {
  QueryAuditLogsInput,
  ExportAuditLogsInput,
  VerifyAuditChainInput,
} from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuditWriterService } from './audit-writer.service.js';
import {
  AuditVerifierService,
  type PartitionVerificationResult,
} from './audit-verifier.service.js';
import {
  applyAuditFilterAllowlist,
  formatAuditExportPayload,
  serializeAuditLogRow,
} from './audit-export.helper.js';
import { createPartitionAnchor, type CreatedAuditAnchorDto } from './audit-anchor.helper.js';

export interface PaginatedAuditLogs {
  data: Array<Record<string, unknown>>;
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

export interface SerializedAuditViolation {
  code: string;
  partition: string;
  sequence: string;
  logId?: string;
  expected?: string;
  actual?: string;
  message: string;
}

export interface SerializedPartitionVerificationResult {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  violations: SerializedAuditViolation[];
  alertId?: string | undefined;
}

/**
 * Thuật toán: Tuần tự hóa kết quả kiểm chứng chuỗi băm kiểm toán sang JSON-safe DTO.
 * Giữ nguyên kiểu `bigint` bên trong `AuditVerifierService` cho kiểm thử đơn vị nhưng chuyển `sequence` và `logId`
 * sang chuỗi thập phân tại ranh giới `AuditService.verifyChain` để ngăn lỗi Fastify `JSON.stringify` BigInt HTTP 500.
 */
function serializeVerificationResult(
  result: PartitionVerificationResult,
): SerializedPartitionVerificationResult {
  // CONFLICT-RESOLVED: Chuyển đổi BigInt sequence/logId trong violations sang chuỗi JSON-safe mà vẫn bảo toàn giao diện nội bộ của AuditVerifierService.
  return {
    partition: result.partition,
    valid: result.valid,
    totalChecked: result.totalChecked,
    anchorsChecked: result.anchorsChecked,
    ...(result.alertId !== undefined ? { alertId: result.alertId } : {}),
    violations: result.violations.map((v) => ({
      code: v.code,
      partition: v.partition,
      sequence: v.sequence.toString(),
      ...(v.logId !== undefined ? { logId: v.logId.toString() } : {}),
      ...(v.expected !== undefined ? { expected: v.expected } : {}),
      ...(v.actual !== undefined ? { actual: v.actual } : {}),
      message: v.message,
    })),
  };
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AuditService {
  private readonly database: PrismaClient;

  constructor(
    private readonly writerService: AuditWriterService,
    private readonly verifierService: AuditVerifierService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Algorithm / Thuật toán: Truy vấn nhật ký kiểm toán phân trang ổn định kèm cô lập phạm vi chống IDOR (Role-Scoped Paginated Audit Query).
   *   1. Kiểm tra vai trò (`SECURITY_OFFICER`/`AUDITOR` xem toàn cục; `DOCUMENT_OWNER` bị giới hạn vào tài liệu sở hữu).
   *   2. Áp bộ lọc danh sách trắng và sắp xếp ổn định có khóa phá hòa `(sortField, id)`.
   */
  async queryAuditLogs(
    principal: AuthPrincipal,
    query: QueryAuditLogsInput,
  ): Promise<PaginatedAuditLogs> {
    const isGlobalAuditor = principal.roles.some(
      (r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR',
    );
    const isDocumentOwner = principal.roles.includes('DOCUMENT_OWNER');

    if (!isGlobalAuditor && !isDocumentOwner) {
      throw new ForbiddenException('Insufficient permissions to view audit logs');
    }

    const where: Prisma.AuditLogWhereInput = {};

    if (!isGlobalAuditor && isDocumentOwner) {
      if (query.documentId) {
        const doc = await this.database.document.findUnique({
          where: { id: query.documentId },
          select: { owner_id: true },
        });
        if (!doc || doc.owner_id !== principal.userId) {
          throw new ForbiddenException('Access to audit logs for this document is denied');
        }
        where.document_id = query.documentId;
      } else {
        const ownedDocs = await this.database.document.findMany({
          where: { owner_id: principal.userId },
          select: { id: true },
        });
        where.document_id = { in: ownedDocs.map((d) => d.id) };
      }
    } else if (query.documentId) {
      where.document_id = query.documentId;
    }

    applyAuditFilterAllowlist(where, query);

    const total = await this.database.auditLog.count({ where });
    const skip = (query.page - 1) * query.pageSize;
    const sortField = query.sort === 'chain_sequence' ? 'chain_sequence' : 'occurred_at';
    const sortOrder = query.order === 'asc' ? 'asc' : 'desc';

    const logs = await this.database.auditLog.findMany({
      where,
      skip,
      take: query.pageSize,
      orderBy: [{ [sortField]: sortOrder }, { id: sortOrder }],
    });

    return {
      data: logs.map(serializeAuditLogRow),
      pagination: {
        page: query.page,
        pageSize: query.pageSize,
        total,
        totalPages: Math.ceil(total / query.pageSize),
      },
    };
  }

  /**
   * Algorithm / Thuật toán: Xuất báo cáo nhật ký kiểm toán sang CSV/JSON dành riêng cho `AUDITOR`.
   */
  async exportAuditLogs(
    principal: AuthPrincipal,
    input: ExportAuditLogsInput,
  ): Promise<{ format: 'CSV' | 'JSON'; data: string; count: number }> {
    if (!principal.roles.includes('AUDITOR')) {
      throw new ForbiddenException('Insufficient permissions to export audit logs');
    }

    const where: Prisma.AuditLogWhereInput = {};
    if (input.documentId) where.document_id = input.documentId;
    applyAuditFilterAllowlist(where, input);

    const logs = await this.database.auditLog.findMany({
      where,
      take: input.limit,
      orderBy: [{ occurred_at: 'desc' }, { id: 'desc' }],
    });

    return formatAuditExportPayload(logs, input.format);
  }

  /**
   * Algorithm / Thuật toán: Tạo điểm neo chữ ký HMAC cho phân vùng nhật ký kiểm toán.
   */
  async createAnchor(principal: AuthPrincipal, partition: string): Promise<CreatedAuditAnchorDto> {
    return createPartitionAnchor(this.database, this.writerService, principal, partition);
  }

  /**
   * Algorithm / Thuật toán: Điều phối kiểm chứng toàn vẹn chuỗi băm cho một hoặc toàn bộ phân vùng.
   */
  async verifyChain(
    principal: AuthPrincipal,
    input: VerifyAuditChainInput,
  ): Promise<
    SerializedPartitionVerificationResult | Record<string, SerializedPartitionVerificationResult>
  > {
    const isPrivileged = principal.roles.some((r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR');
    if (!isPrivileged) {
      throw new ForbiddenException('Only Security Officer or Auditor can verify audit chains');
    }

    if (input.chainPartition) {
      const options: { fromSequence?: bigint; toSequence?: bigint } = {};
      if (input.fromSequence !== undefined) options.fromSequence = input.fromSequence;
      if (input.toSequence !== undefined) options.toSequence = input.toSequence;
      const single = await this.verifierService.verifyPartition(input.chainPartition, options);
      return serializeVerificationResult(single);
    }

    const all = await this.verifierService.verifyAllPartitions();
    return Object.fromEntries(
      Object.entries(all).map(([partition, res]) => [partition, serializeVerificationResult(res)]),
    );
  }
}
