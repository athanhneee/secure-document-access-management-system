import { getDatabaseClient, withSerializableTransaction, type Prisma } from '@sda/database';
import { buildAuditKeyRing, canonicalizeJson } from '@sda/contracts';
import { createHmac, randomUUID } from 'node:crypto';

/**
 * Grant Expiry Job (D-BR15 Defense-in-Depth)
 *
 * Algorithm / Thuật toán tổng quan module:
 * - Định kỳ quét bảng `access_grants` để thu hồi tự động theo lô (`BATCH_SIZE = 100`) các quyền truy cập hết hạn
 *   (`status = 'ACTIVE'` và `valid_until <= now`) kết hợp khóa hàng `FOR UPDATE SKIP LOCKED` và vòng lặp thử lại `withSerializableTransaction` (`40001`).
 * - Chấm dứt dây chuyền phiên truy cập đang mở (`access_sessions`), xin khóa tư vấn giao dịch 64-bit `pg_advisory_xact_lock(hashtextextended($1, 0))`
 *   đúng một lần cho phân vùng trước vòng lặp, chuẩn hóa JSON tất định RFC 8785 (`canonicalizeJson`) và nối chuỗi băm kiểm toán mật mã HMAC-SHA256.
 */

const BATCH_SIZE = 100;

interface ExpiredGrantRow {
  id: string;
  document_id: string;
  principal_user_id: bigint | null;
  principal_role_id: bigint | null;
  principal_type: string;
}

interface AuditChainRow {
  entry_hash: string;
  chain_sequence: bigint;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Thu hồi theo lô quyền truy cập hết hạn trong giao dịch `SERIALIZABLE` có thử lại xung đột `40001`
 * và ghi nhật ký chuỗi băm kiểm toán nguyên tử dưới khóa tư vấn 64-bit `hashtextextended`.
 */
export async function runGrantExpiryBatch(
  hmacKey: string,
  keyRotationJson?: string,
  options?: { databaseClient?: PrismaClient; maxRetries?: number },
): Promise<number> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const keyRing = buildAuditKeyRing(hmacKey, keyRotationJson);
  const now = new Date();

  return withSerializableTransaction(
    async (tx: Prisma.TransactionClient) => {
      const expiring = await tx.$queryRawUnsafe<ExpiredGrantRow[]>(
        `SELECT id, document_id, principal_user_id, principal_role_id, principal_type
         FROM access_grants
         WHERE status = 'ACTIVE' AND valid_until <= $1
         LIMIT $2
         FOR UPDATE SKIP LOCKED`,
        now,
        BATCH_SIZE,
      );

      if (expiring.length === 0) return 0;

      const ids = expiring.map((r: ExpiredGrantRow) => r.id);
      await tx.accessGrant.updateMany({
        where: { id: { in: ids } },
        data: { status: 'EXPIRED' },
      });

      const activeSessions = await tx.accessSession.findMany({
        where: { access_grant_id: { in: ids }, status: 'ACTIVE' },
        select: { id: true, user_id: true, access_grant_id: true },
      });

      if (activeSessions.length > 0) {
        await tx.accessSession.updateMany({
          where: { access_grant_id: { in: ids }, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Grant expired',
          },
        });
      }

      const partition = 'ACCESS_GRANT';
      // CONFLICT-RESOLVED: Sử dụng khóa tư vấn 64-bit hashtextextended($1, 0) đồng nhất với trigger validate_audit_chain_link() và chỉ khóa 1 lần cho phân vùng trước vòng lặp.
      await tx.$executeRawUnsafe(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        partition,
      );

      const previous = await tx.$queryRawUnsafe<AuditChainRow[]>(
        'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
        partition,
      );
      const prior = previous[0] as AuditChainRow | undefined;
      let currentSequence = BigInt(prior?.chain_sequence ?? 0n);
      let currentPreviousHash = prior?.entry_hash ?? null;

      for (const grant of expiring) {
        const sequence = ++currentSequence;
        const previousHash = currentPreviousHash;
        const correlationId = randomUUID();
        const occurredAt = new Date();

        const sessionCount = activeSessions.filter(
          (session) => session.access_grant_id === grant.id,
        ).length;

        const details: Record<string, string | number | boolean | null> = {
          principalType: grant.principal_type,
          principalUserId: grant.principal_user_id?.toString() ?? null,
          principalRoleId: grant.principal_role_id?.toString() ?? null,
          terminatedSessions: sessionCount,
          batchExpiry: true,
        };

        const canonical = canonicalizeJson({
          action: 'GRANT_EXPIRED',
          actorUserId: null,
          actorUsername: 'SYSTEM_WORKER',
          chainAlgorithm: 'HMAC-SHA-256',
          chainPartition: partition,
          chainSequence: sequence.toString(),
          correlationId,
          details,
          documentId: grant.document_id,
          accessSessionId: null,
          ipAddress: '127.0.0.1',
          objectType: 'ACCESS_GRANT',
          objectId: grant.id,
          occurredAt: occurredAt.toISOString(),
          outcome: 'SUCCESS',
          previousHash,
          reasonCode: 'GRANT_VALIDITY_EXPIRED',
          userAgent: null,
        });

        const entryHash = createHmac('sha256', keyRing.activeKey)
          .update(canonical, 'utf8')
          .digest('hex');

        await tx.auditLog.create({
          data: {
            occurred_at: occurredAt,
            actor_user_id: null,
            actor_username: 'SYSTEM_WORKER',
            action: 'GRANT_EXPIRED',
            object_type: 'ACCESS_GRANT',
            object_id: grant.id,
            document_id: grant.document_id,
            access_session_id: null,
            outcome: 'SUCCESS',
            reason_code: 'GRANT_VALIDITY_EXPIRED',
            ip_address: '127.0.0.1',
            user_agent: null,
            correlation_id: correlationId,
            details,
            previous_hash: previousHash,
            entry_hash: entryHash,
            chain_partition: partition,
            chain_sequence: sequence,
            hmac_key_version: keyRing.activeVersion,
            chain_algorithm: 'HMAC-SHA-256',
          },
        });

        currentPreviousHash = entryHash;
      }

      return expiring.length;
    },
    {
      client: database,
      ...(options?.maxRetries !== undefined
        ? { maxRetries: options.maxRetries, baseDelayMs: 1 }
        : {}),
    },
  );
}

/**
 * Algorithm / Thuật toán: Điều phối vòng lặp định thời chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler).
 */
export function startGrantExpiryJob(
  intervalMs: number,
  hmacKey: string,
  signal: AbortSignal,
  keyRotationJson?: string,
): void {
  let isRunning = false;
  const tick = async (): Promise<void> => {
    if (isRunning || signal.aborted) return;
    isRunning = true;
    try {
      const count = await runGrantExpiryBatch(hmacKey, keyRotationJson);
      if (count > 0) {
        console.info(`Grant expiry worker: expired ${count} grants.`);
      }
    } catch (err: unknown) {
      console.error('Grant expiry worker error:', err instanceof Error ? err.message : String(err));
    } finally {
      isRunning = false;
    }
  };

  const timer = setInterval(() => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    void tick();
  }, intervalMs);

  signal.addEventListener('abort', () => clearInterval(timer), { once: true });
  console.info(`Grant expiry worker started (interval: ${intervalMs}ms).`);
}
