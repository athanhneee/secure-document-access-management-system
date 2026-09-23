import { createHmac } from 'node:crypto';
import { ForbiddenException, Injectable, NotFoundException, Optional } from '@nestjs/common';
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

export interface PaginatedAuditLogs {
  data: Array<Record<string, unknown>>;
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
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
   * Queries audit logs with strict allowlist filtering, stable pagination,
   * and role-based scope enforcement (Global for Security/Auditor, document-scoped for Owner).
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

    // 1. Enforce Document Owner scope restriction (IDOR prevention)
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
        const ownedIds = ownedDocs.map((d) => d.id);
        where.document_id = { in: ownedIds };
      }
    } else if (query.documentId) {
      where.document_id = query.documentId;
    }

    // 2. Apply Allowlist Filters
    if (query.actorUserId !== undefined) {
      where.actor_user_id = query.actorUserId;
    }
    if (query.action) {
      where.action = query.action;
    }
    if (query.outcome) {
      where.outcome = query.outcome;
    }
    if (query.chainPartition) {
      where.chain_partition = query.chainPartition;
    }
    if (query.from || query.to) {
      where.occurred_at = {};
      if (query.from) {
        where.occurred_at.gte = new Date(query.from);
      }
      if (query.to) {
        where.occurred_at.lte = new Date(query.to);
      }
    }

    // 3. Count total matching rows
    const total = await this.database.auditLog.count({ where });

    // 4. Fetch paginated records with stable tie-breaker ordering
    const skip = (query.page - 1) * query.pageSize;
    const take = query.pageSize;

    const sortField = query.sort === 'chain_sequence' ? 'chain_sequence' : 'occurred_at';
    const sortOrder = query.order === 'asc' ? 'asc' : 'desc';

    const logs = await this.database.auditLog.findMany({
      where,
      skip,
      take,
      orderBy: [{ [sortField]: sortOrder }, { id: sortOrder }],
    });

    // 5. Serialize records, converting BigInt to string
    const data = logs.map((log) => ({
      id: log.id.toString(),
      occurredAt: log.occurred_at.toISOString(),
      actorUserId: log.actor_user_id?.toString() ?? null,
      actorUsername: log.actor_username,
      action: log.action,
      objectType: log.object_type,
      objectId: log.object_id,
      documentId: log.document_id,
      accessSessionId: log.access_session_id,
      outcome: log.outcome,
      reasonCode: log.reason_code,
      ipAddress: log.ip_address,
      userAgent: log.user_agent,
      correlationId: log.correlation_id,
      details: log.details,
      chainPartition: log.chain_partition,
      chainSequence: log.chain_sequence.toString(),
      entryHash: log.entry_hash,
      previousHash: log.previous_hash,
      hmacKeyVersion: log.hmac_key_version,
      chainAlgorithm: log.chain_algorithm,
    }));

    return {
      data,
      pagination: {
        page: query.page,
        pageSize: query.pageSize,
        total,
        totalPages: Math.ceil(total / query.pageSize),
      },
    };
  }

  /**
   * Exports audit logs in CSV or JSON format.
   */
  async exportAuditLogs(
    principal: AuthPrincipal,
    input: ExportAuditLogsInput,
  ): Promise<{ format: 'CSV' | 'JSON'; data: string; count: number }> {
    const isAuditor = principal.roles.includes('AUDITOR');
    const isDocumentOwner = principal.roles.includes('DOCUMENT_OWNER');

    if (!isAuditor && !isDocumentOwner) {
      throw new ForbiddenException('Insufficient permissions to export audit logs');
    }

    const where: Prisma.AuditLogWhereInput = {};

    if (!isAuditor && isDocumentOwner) {
      if (input.documentId) {
        const doc = await this.database.document.findUnique({
          where: { id: input.documentId },
          select: { owner_id: true },
        });
        if (!doc || doc.owner_id !== principal.userId) {
          throw new ForbiddenException('Access to audit logs for this document is denied');
        }
        where.document_id = input.documentId;
      } else {
        const ownedDocs = await this.database.document.findMany({
          where: { owner_id: principal.userId },
          select: { id: true },
        });
        where.document_id = { in: ownedDocs.map((d) => d.id) };
      }
    } else if (input.documentId) {
      where.document_id = input.documentId;
    }

    if (input.actorUserId !== undefined) where.actor_user_id = input.actorUserId;
    if (input.action) where.action = input.action;
    if (input.outcome) where.outcome = input.outcome;
    if (input.chainPartition) where.chain_partition = input.chainPartition;
    if (input.from || input.to) {
      where.occurred_at = {};
      if (input.from) where.occurred_at.gte = new Date(input.from);
      if (input.to) where.occurred_at.lte = new Date(input.to);
    }

    const logs = await this.database.auditLog.findMany({
      where,
      take: input.limit,
      orderBy: [{ occurred_at: 'desc' }, { id: 'desc' }],
    });

    if (input.format === 'CSV') {
      const headers = [
        'id',
        'occurred_at',
        'actor_user_id',
        'actor_username',
        'action',
        'object_type',
        'object_id',
        'document_id',
        'access_session_id',
        'outcome',
        'reason_code',
        'ip_address',
        'correlation_id',
        'chain_partition',
        'chain_sequence',
        'entry_hash',
      ];

      const escapeCsv = (val: unknown): string => {
        if (val === null || val === undefined) return '';
        const str = String(val);
        if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      };

      const rows = [headers.join(',')];
      for (const log of logs) {
        rows.push(
          [
            log.id.toString(),
            log.occurred_at.toISOString(),
            log.actor_user_id?.toString() ?? '',
            escapeCsv(log.actor_username),
            escapeCsv(log.action),
            escapeCsv(log.object_type),
            escapeCsv(log.object_id),
            log.document_id ?? '',
            log.access_session_id ?? '',
            log.outcome,
            escapeCsv(log.reason_code),
            log.ip_address ?? '',
            log.correlation_id,
            escapeCsv(log.chain_partition),
            log.chain_sequence.toString(),
            log.entry_hash,
          ].join(','),
        );
      }

      return {
        format: 'CSV',
        data: rows.join('\r\n'),
        count: logs.length,
      };
    }

    // Default JSON export
    const jsonOutput = logs.map((log) => ({
      id: log.id.toString(),
      occurredAt: log.occurred_at.toISOString(),
      actorUserId: log.actor_user_id?.toString() ?? null,
      actorUsername: log.actor_username,
      action: log.action,
      objectType: log.object_type,
      objectId: log.object_id,
      documentId: log.document_id,
      accessSessionId: log.access_session_id,
      outcome: log.outcome,
      reasonCode: log.reason_code,
      ipAddress: log.ip_address,
      userAgent: log.user_agent,
      correlationId: log.correlation_id,
      details: log.details,
      chainPartition: log.chain_partition,
      chainSequence: log.chain_sequence.toString(),
      entryHash: log.entry_hash,
      previousHash: log.previous_hash,
      hmacKeyVersion: log.hmac_key_version,
      chainAlgorithm: log.chain_algorithm,
    }));

    return {
      format: 'JSON',
      data: JSON.stringify(jsonOutput, null, 2),
      count: logs.length,
    };
  }

  /**
   * Creates a signed checkpoint anchor for a partition.
   */
  async createAnchor(
    principal: AuthPrincipal,
    partition: string,
  ): Promise<{
    id: string;
    chainPartition: string;
    anchorSequence: string;
    entryHash: string;
    signature: string;
    anchoredAt: string;
  }> {
    const isPrivileged = principal.roles.some((r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR');
    if (!isPrivileged) {
      throw new ForbiddenException('Only Security Officer or Auditor can create audit anchors');
    }

    // Find the latest audit log in this partition
    const latestLog = await this.database.auditLog.findFirst({
      where: { chain_partition: partition },
      orderBy: { chain_sequence: 'desc' },
    });

    if (!latestLog) {
      throw new NotFoundException(`No audit logs found for partition ${partition}`);
    }

    // Sign the anchor with the active HMAC integrity key
    const anchorKey = this.writerService.getHmacKey(1);
    const signature = createHmac('sha256', anchorKey)
      .update(`${partition}:${latestLog.chain_sequence}:${latestLog.entry_hash}`)
      .digest('hex');

    const created = await this.database.auditAnchor.create({
      data: {
        chain_partition: partition,
        anchor_sequence: latestLog.chain_sequence,
        entry_hash: latestLog.entry_hash,
        signature,
        signer_key_id: 'integrity-key-v1',
        status: 'VALID',
      },
    });

    return {
      id: created.id.toString(),
      chainPartition: created.chain_partition,
      anchorSequence: created.anchor_sequence.toString(),
      entryHash: created.entry_hash,
      signature: created.signature,
      anchoredAt: created.anchored_at.toISOString(),
    };
  }

  /**
   * Verifies partition integrity and returns verification report.
   */
  async verifyChain(
    principal: AuthPrincipal,
    input: VerifyAuditChainInput,
  ): Promise<PartitionVerificationResult | Record<string, PartitionVerificationResult>> {
    const isPrivileged = principal.roles.some((r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR');
    if (!isPrivileged) {
      throw new ForbiddenException('Only Security Officer or Auditor can verify audit chains');
    }

    if (input.chainPartition) {
      const options: { fromSequence?: bigint; toSequence?: bigint } = {};
      if (input.fromSequence !== undefined) options.fromSequence = input.fromSequence;
      if (input.toSequence !== undefined) options.toSequence = input.toSequence;
      return await this.verifierService.verifyPartition(input.chainPartition, options);
    }

    return await this.verifierService.verifyAllPartitions();
  }
}
