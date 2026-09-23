import { getDatabaseClient } from '@sda/database';
import { createHmac, randomUUID } from 'node:crypto';

/**
 * Grant Expiry Job
 *
 * Scans for ACTIVE access_grants past valid_until and transitions them to EXPIRED.
 * Also terminates related ACTIVE access_sessions.
 *
 * D-BR15: Worker hết hạn grant theo lịch, nhưng mỗi request truy cập vẫn tự kiểm tra
 * thời gian để không phụ thuộc worker. Worker là defense-in-depth.
 *
 * Runs on a configurable interval (GRANT_EXPIRY_INTERVAL_MS, default 60s).
 * Each run processes up to BATCH_SIZE grants with FOR UPDATE SKIP LOCKED
 * to support concurrent worker instances.
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
type TransactionClient = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

export async function runGrantExpiryBatch(hmacKey: string): Promise<number> {
  const database = getDatabaseClient();
  const now = new Date();
  let expiredCount = 0;

  await database.$transaction(
    async (tx: TransactionClient) => {
      // Select grants to expire with row locking, skip already-locked rows
      const expiring = await tx.$queryRawUnsafe<ExpiredGrantRow[]>(
        `SELECT id, document_id, principal_user_id, principal_role_id, principal_type
         FROM access_grants
         WHERE status = 'ACTIVE' AND valid_until <= $1
         LIMIT $2
         FOR UPDATE SKIP LOCKED`,
        now,
        BATCH_SIZE,
      );

      if (expiring.length === 0) return;

      const ids = expiring.map((r: ExpiredGrantRow) => r.id);

      // Batch update grants to EXPIRED
      const result = await tx.accessGrant.updateMany({
        where: { id: { in: ids } },
        data: { status: 'EXPIRED' },
      });
      expiredCount = result.count;

      // Terminate related active sessions
      const activeSessions = await tx.accessSession.findMany({
        where: {
          access_grant_id: { in: ids },
          status: 'ACTIVE',
        },
        select: { id: true, user_id: true },
      });

      if (activeSessions.length > 0) {
        await tx.accessSession.updateMany({
          where: {
            access_grant_id: { in: ids },
            status: 'ACTIVE',
          },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Grant expired',
          },
        });
      }

      // Record audit for each expired grant
      for (const grant of expiring) {
        const partition = 'ACCESS_GRANT';
        await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);

        const previous = await tx.$queryRawUnsafe<AuditChainRow[]>(
          'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
          partition,
        );
        const prior = previous[0] as AuditChainRow | undefined;
        const sequence = (prior?.chain_sequence ?? 0n) + 1n;
        const correlationId = randomUUID();

        const sessionCount = activeSessions.filter(
          (_session) => true, // all sessions in this batch relate to these grants
        ).length;

        const details: Record<string, string | number | boolean | null> = {
          principalType: grant.principal_type,
          principalUserId: grant.principal_user_id?.toString() ?? null,
          principalRoleId: grant.principal_role_id?.toString() ?? null,
          terminatedSessions: sessionCount,
          batchExpiry: true,
        };

        const canonical = JSON.stringify({
          action: 'GRANT_EXPIRED',
          actorUserId: null,
          actorUsername: 'SYSTEM_WORKER',
          correlationId,
          details,
          documentId: grant.document_id,
          objectId: grant.id,
          outcome: 'SUCCESS',
          previousHash: prior?.entry_hash ?? null,
          reasonCode: 'GRANT_VALIDITY_EXPIRED',
          sequence: sequence.toString(),
        });

        const entryHash = createHmac('sha256', hmacKey).update(canonical).digest('hex');

        await tx.auditLog.create({
          data: {
            actor_user_id: null,
            actor_username: 'SYSTEM_WORKER',
            action: 'GRANT_EXPIRED',
            object_type: 'ACCESS_GRANT',
            object_id: grant.id,
            document_id: grant.document_id,
            outcome: 'SUCCESS',
            reason_code: 'GRANT_VALIDITY_EXPIRED',
            ip_address: '127.0.0.1',
            correlation_id: correlationId,
            details,
            previous_hash: prior?.entry_hash ?? null,
            entry_hash: entryHash,
            chain_partition: partition,
            chain_sequence: sequence,
            hmac_key_version: 1,
          },
        });
      }
    },
    { isolationLevel: 'Serializable' },
  );

  return expiredCount;
}

/**
 * Start the grant expiry job loop. Runs until the AbortSignal fires.
 */
export function startGrantExpiryJob(
  intervalMs: number,
  hmacKey: string,
  signal: AbortSignal,
): void {
  const tick = async (): Promise<void> => {
    try {
      const count = await runGrantExpiryBatch(hmacKey);
      if (count > 0) {
        console.info(`Grant expiry worker: expired ${count} grants.`);
      }
    } catch (err: unknown) {
      console.error('Grant expiry worker error:', err instanceof Error ? err.message : String(err));
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
