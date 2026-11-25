/**
 * @module AuditAnchorHelper
 * Algorithm: HMAC-SHA256 Signed Checkpoint Anchor Generation for Audit Chain Partitions.
 */
import { createHmac } from 'node:crypto';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { formatSignerKeyId } from '@sda/contracts';
import type { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { AuditWriterService } from './audit-writer.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface CreatedAuditAnchorDto {
  id: string;
  chainPartition: string;
  anchorSequence: string;
  entryHash: string;
  signature: string;
  signerKeyId?: string | undefined;
  status?: string | undefined;
  anchoredAt: string;
}

/**
 * Algorithm / Thuật toán: Liệt kê các điểm neo kiểm chứng chuỗi băm kiểm toán (`listPartitionAnchors`) cho `SECURITY_OFFICER`, `AUDITOR` và vai trò tùy chỉnh có `AUDIT_LOG:VIEW` (UC32, #04).
 */
export async function listPartitionAnchors(
  database: PrismaClient,
  principal: AuthPrincipal,
  partition?: string,
  authorization?: AuthorizationService,
): Promise<{ data: CreatedAuditAnchorDto[] }> {
  const isPrivilegedRole = principal.roles.some((r) => r === 'SECURITY_OFFICER' || r === 'AUDITOR');
  const isCustomAuditor =
    !isPrivilegedRole &&
    !principal.roles.includes('DOCUMENT_OWNER') &&
    Boolean(
      authorization &&
      (await authorization.hasPermission(principal, 'AUDIT_LOG', 'VIEW', { anyScope: true })),
    );
  if (!isPrivilegedRole && !isCustomAuditor) {
    throw new ForbiddenException('Only Security Officer or Auditor can view audit anchors');
  }
  const rows = await database.auditAnchor.findMany({
    ...(partition?.trim() ? { where: { chain_partition: partition.trim() } } : {}),
    orderBy: [{ anchored_at: 'desc' }, { id: 'desc' }],
    take: 100,
  });
  return {
    data: rows.map((row) => ({
      id: row.id.toString(),
      chainPartition: row.chain_partition,
      anchorSequence: row.anchor_sequence.toString(),
      entryHash: row.entry_hash,
      signature: row.signature,
      signerKeyId: row.signer_key_id,
      status: row.status,
      anchoredAt: row.anchored_at.toISOString(),
    })),
  };
}

/**
 * Algorithm / Thuật toán: Khởi tạo điểm neo kiểm chứng có chữ ký mật mã (Signed Checkpoint Anchor Creation).
 * Cơ chế hoạt động:
 *   1. Cưỡng chế phân quyền độc quyền cho vai trò `SECURITY_OFFICER`.
 *   2. Truy vấn mắt xích mới nhất (`chain_sequence DESC`) của phân vùng cần đóng dấu neo.
 *   3. Ký `HMAC-SHA256` trên bộ ba `partition:sequence:entry_hash` và lưu vào bảng `audit_anchors`.
 */
export async function createPartitionAnchor(
  database: PrismaClient,
  writerService: AuditWriterService,
  principal: AuthPrincipal,
  partition: string,
): Promise<CreatedAuditAnchorDto> {
  const isSecurityOfficer = principal.roles.includes('SECURITY_OFFICER');
  if (!isSecurityOfficer) {
    throw new ForbiddenException('Only Security Officer can create audit anchors');
  }

  const latestLog = await database.auditLog.findFirst({
    where: { chain_partition: partition },
    orderBy: { chain_sequence: 'desc' },
  });

  if (!latestLog) {
    throw new NotFoundException(`No audit logs found for partition ${partition}`);
  }

  // CONFLICT-RESOLVED: Ký điểm neo audit_anchors bằng phiên bản khóa HMAC đang kích hoạt (activeVersion) và ghi đúng định danh signer_key_id thay vì gắn cứng phiên bản 1.
  const activeKeyVersion = writerService.getActiveKeyVersion();
  const anchorKey = writerService.getHmacKey(activeKeyVersion);
  const signature = createHmac('sha256', anchorKey)
    .update(`${partition}:${latestLog.chain_sequence}:${latestLog.entry_hash}`)
    .digest('hex');

  const created = await database.auditAnchor.create({
    data: {
      chain_partition: partition,
      anchor_sequence: latestLog.chain_sequence,
      entry_hash: latestLog.entry_hash,
      signature,
      signer_key_id: formatSignerKeyId(activeKeyVersion),
      status: 'VALID',
    },
  });

  if (typeof writerService?.writeLog === 'function') {
    await writerService
      .writeLog({
        actorUserId: principal.userId,
        actorUsername: principal.username,
        action: 'AUDIT_ANCHOR_CREATED',
        objectType: 'AUDIT_ANCHOR',
        objectId: created.id.toString(),
        outcome: 'SUCCESS',
        chainPartition: 'AUDIT',
        details: {
          chainPartition: created.chain_partition,
          anchorSequence: created.anchor_sequence.toString(),
          signerKeyId: created.signer_key_id,
        },
      })
      .catch(() => {});
  }

  return {
    id: created.id.toString(),
    chainPartition: created.chain_partition,
    anchorSequence: created.anchor_sequence.toString(),
    entryHash: created.entry_hash,
    signature: created.signature,
    signerKeyId: created.signer_key_id,
    status: created.status,
    anchoredAt: created.anchored_at.toISOString(),
  };
}
