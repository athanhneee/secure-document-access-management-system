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
import { AuthorizationService } from '../rbac/authorization.service.js';
import { AuditWriterService } from './audit-writer.service.js';
import {
  AuditVerifierService,
  type PartitionVerificationResult,
} from './audit-verifier.service.js';
import { redactOracleField } from './audit-alert-escalator.js';
import {
  applyAuditFilterAllowlist,
  formatAuditExportPayload,
  serializeAuditLogRow,
} from './audit-export.helper.js';
import {
  createPartitionAnchor,
  listPartitionAnchors,
  type CreatedAuditAnchorDto,
} from './audit-anchor.helper.js';

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
  resumedFromAnchorSequence?: string | undefined;
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
    ...(result.resumedFromAnchorSequence !== undefined
      ? { resumedFromAnchorSequence: result.resumedFromAnchorSequence }
      : {}),
    ...(result.alertId !== undefined ? { alertId: result.alertId } : {}),
    violations: result.violations.map((v) => {
      const safeExpected = redactOracleField(v.code, v.expected);
      const safeActual = v.code === 'AUDIT_LOG_TAMPERED' ? '[TAMPERED_ENTRY_HASH]' : v.actual;
      return {
        code: v.code,
        partition: v.partition,
        sequence: v.sequence.toString(),
        ...(v.logId !== undefined ? { logId: v.logId.toString() } : {}),
        ...(safeExpected !== undefined ? { expected: safeExpected } : {}),
        ...(safeActual !== undefined ? { actual: safeActual } : {}),
        message: v.message,
      };
    }),
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
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Xác định phạm vi xem kiểm toán (Toàn cục / Phòng ban / Chủ tài liệu) hỗ trợ Custom Role RBAC.
   */
  private async hasAuditPermission(
    principal: AuthPrincipal,
    action: 'VIEW' | 'EXPORT',
  ): Promise<boolean> {
    if (!this.authorization) return false;
    return this.authorization.hasPermission(principal, 'AUDIT_LOG', action, { anyScope: true });
  }

  /**
   * Thuật toán: Ghi nhật ký kiểm toán-của-kiểm toán (`Audit-of-Audit`) không làm gián đoạn phản hồi nếu writer mock không hỗ trợ.
   */
  private async recordAuditOfAudit(
    principal: AuthPrincipal,
    action: 'AUDIT_CHAIN_VERIFIED' | 'AUDIT_LOG_EXPORTED',
    details: Record<string, unknown>,
  ): Promise<void> {
    if (typeof this.writerService?.writeLog !== 'function') return;
    await this.writerService
      .writeLog({
        actorUserId: principal.userId,
        actorUsername: principal.username,
        action,
        objectType: 'AUDIT_LOG',
        outcome: 'SUCCESS',
        chainPartition: 'AUDIT',
        details,
      })
      .catch(() => {});
  }

  /**
   * Algorithm / Thuật toán: Truy vấn nhật ký kiểm toán phân trang ổn định kèm cô lập phạm vi chống IDOR (Role & Permission-Scoped Paginated Audit Query).
   *   1. Hỗ trợ `SECURITY_OFFICER`, `AUDITOR` và Custom Role có `AUDIT_LOG:VIEW` (kèm bao đóng phòng ban nếu bị giới hạn phạm vi).
   *   2. Giữ cô lập tài liệu sở hữu + ẩn `WATERMARK_TRACE_PERFORMED` cho `DOCUMENT_OWNER`.
   *   3. Áp bộ lọc danh sách trắng và sắp xếp ổn định có khóa phá hòa `(sortField, id)`.
   */
  async queryAuditLogs(
    principal: AuthPrincipal,
    query: QueryAuditLogsInput,
  ): Promise<PaginatedAuditLogs> {
    const isPrivilegedRole = principal.roles.some(
      (r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR',
    );
    const isDocumentOwner = principal.roles.includes('DOCUMENT_OWNER');
    const isCustomAuditor =
      !isPrivilegedRole && !isDocumentOwner && (await this.hasAuditPermission(principal, 'VIEW'));
    const isGlobalOrScopedAuditor = isPrivilegedRole || isCustomAuditor;

    if (!isGlobalOrScopedAuditor && !isDocumentOwner) {
      throw new ForbiddenException('Insufficient permissions to view audit logs');
    }

    const where: Prisma.AuditLogWhereInput = {};

    if (!isGlobalOrScopedAuditor && isDocumentOwner) {
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
    } else {
      if (query.documentId) {
        where.document_id = query.documentId;
      }
      if (this.authorization) {
        const visibleDeptIds = await this.authorization.visibleDepartmentIds(
          principal,
          'AUDIT_LOG',
          'VIEW',
        );
        if (visibleDeptIds !== null) {
          if (visibleDeptIds.length === 0) {
            return {
              data: [],
              pagination: { page: query.page, pageSize: query.pageSize, total: 0, totalPages: 0 },
            };
          }
          where.OR = [
            { users: { department_id: { in: visibleDeptIds } } },
            { documents: { department_id: { in: visibleDeptIds } } },
          ];
        }
      }
    }

    applyAuditFilterAllowlist(where, query);

    if (!isGlobalOrScopedAuditor && isDocumentOwner) {
      const normalizedAction = query.action?.trim();
      if (normalizedAction?.toUpperCase() === 'WATERMARK_TRACE_PERFORMED') {
        where.action = { in: [], notIn: ['WATERMARK_TRACE_PERFORMED'] };
      } else if (normalizedAction) {
        where.action = {
          contains: normalizedAction,
          mode: 'insensitive',
          notIn: ['WATERMARK_TRACE_PERFORMED'],
        };
      } else {
        where.action = { notIn: ['WATERMARK_TRACE_PERFORMED'] };
      }
    }

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
   * Algorithm / Thuật toán: Xuất báo cáo nhật ký kiểm toán sang CSV/JSON cho `AUDITOR` hoặc Custom Role có `AUDIT_LOG:EXPORT` kèm kiểm toán ngược.
   */
  async exportAuditLogs(
    principal: AuthPrincipal,
    input: ExportAuditLogsInput,
  ): Promise<{ format: 'CSV' | 'JSON'; data: string; count: number }> {
    const canExport =
      principal.roles.includes('AUDITOR') || (await this.hasAuditPermission(principal, 'EXPORT'));
    if (!canExport) {
      throw new ForbiddenException('Insufficient permissions to export audit logs');
    }

    const where: Prisma.AuditLogWhereInput = {};
    if (input.documentId) where.document_id = input.documentId;
    if (this.authorization) {
      const visibleDeptIds = await this.authorization.visibleDepartmentIds(
        principal,
        'AUDIT_LOG',
        'EXPORT',
      );
      if (visibleDeptIds !== null) {
        if (visibleDeptIds.length === 0) {
          return formatAuditExportPayload([], input.format);
        }
        where.OR = [
          { users: { department_id: { in: visibleDeptIds } } },
          { documents: { department_id: { in: visibleDeptIds } } },
        ];
      }
    }
    applyAuditFilterAllowlist(where, input);

    const logs = await this.database.auditLog.findMany({
      where,
      take: input.limit,
      orderBy: [{ occurred_at: 'desc' }, { id: 'desc' }],
    });

    const payload = formatAuditExportPayload(logs, input.format);
    await this.recordAuditOfAudit(principal, 'AUDIT_LOG_EXPORTED', {
      format: input.format,
      rowCount: payload.count,
      chainPartition: input.chainPartition ?? null,
    });
    return payload;
  }

  /**
   * Algorithm / Thuật toán: Liệt kê danh sách điểm neo chữ ký HMAC đã khởi tạo cho các phân vùng kiểm toán (UC32).
   */
  async listAnchors(
    principal: AuthPrincipal,
    partition?: string,
  ): Promise<{ data: CreatedAuditAnchorDto[] }> {
    return listPartitionAnchors(this.database, principal, partition, this.authorization);
  }

  /**
   * Algorithm / Thuật toán: Tạo điểm neo chữ ký HMAC cho phân vùng nhật ký kiểm toán.
   */
  async createAnchor(principal: AuthPrincipal, partition: string): Promise<CreatedAuditAnchorDto> {
    return createPartitionAnchor(this.database, this.writerService, principal, partition);
  }

  /**
   * Algorithm / Thuật toán: Điều phối kiểm chứng toàn vẹn chuỗi băm cho một hoặc toàn bộ phân vùng kèm ghi nhận kiểm toán ngược `AUDIT_CHAIN_VERIFIED`.
   */
  async verifyChain(
    principal: AuthPrincipal,
    input: VerifyAuditChainInput,
  ): Promise<
    SerializedPartitionVerificationResult | Record<string, SerializedPartitionVerificationResult>
  > {
    const isPrivilegedRole = principal.roles.some(
      (r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR',
    );
    const isCustomAuditor =
      !isPrivilegedRole &&
      !principal.roles.includes('DOCUMENT_OWNER') &&
      (await this.hasAuditPermission(principal, 'VIEW'));
    if (!isPrivilegedRole && !isCustomAuditor) {
      throw new ForbiddenException('Only Security Officer or Auditor can verify audit chains');
    }

    if (input.chainPartition) {
      const options: { fromSequence?: bigint; toSequence?: bigint } = {};
      if (input.fromSequence !== undefined) options.fromSequence = input.fromSequence;
      if (input.toSequence !== undefined) options.toSequence = input.toSequence;
      const single = await this.verifierService.verifyPartition(input.chainPartition, options);
      const serialized = serializeVerificationResult(single);
      await this.recordAuditOfAudit(principal, 'AUDIT_CHAIN_VERIFIED', {
        scope: input.chainPartition,
        valid: serialized.valid,
        totalChecked: serialized.totalChecked,
        violationCount: serialized.violations.length,
      });
      return serialized;
    }

    const all = await this.verifierService.verifyAllPartitions();
    const serializedAll = Object.fromEntries(
      Object.entries(all).map(([partition, res]) => [partition, serializeVerificationResult(res)]),
    );
    const allResults = Object.values(serializedAll);
    await this.recordAuditOfAudit(principal, 'AUDIT_CHAIN_VERIFIED', {
      scope: 'ALL',
      partitionCount: allResults.length,
      valid: allResults.every((r) => r.valid),
      totalChecked: allResults.reduce((acc, r) => acc + r.totalChecked, 0),
      violationCount: allResults.reduce((acc, r) => acc + r.violations.length, 0),
    });
    return serializedAll;
  }
}
