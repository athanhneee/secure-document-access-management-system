/**
 * @module AuditAnchorHelper
 * Algorithm: HMAC-SHA256 Signed Checkpoint Anchor Generation for Audit Chain Partitions.
 */
import { createHmac } from 'node:crypto';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { formatSignerKeyId } from '@sda/contracts';
import type { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuditWriterService } from './audit-writer.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface CreatedAuditAnchorDto {
  id: string;
  chainPartition: string;
  anchorSequence: string;
  entryHash: string;
  signature: string;
  anchoredAt: string;
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

  return {
    id: created.id.toString(),
    chainPartition: created.chain_partition,
    anchorSequence: created.anchor_sequence.toString(),
    entryHash: created.entry_hash,
    signature: created.signature,
    anchoredAt: created.anchored_at.toISOString(),
  };
}
