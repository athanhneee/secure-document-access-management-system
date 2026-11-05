import { getDatabaseClient, type notification_status } from '@sda/database';
import { randomUUID } from 'node:crypto';
import { deliverOutboxEmailViaSmtp } from './outbox-mailer.helper.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ xử lý hàng đợi thông báo theo mẫu Transactional Outbox kết hợp khóa hàng `FOR UPDATE SKIP LOCKED`,
 * phân phát lũy đẳng (Idempotent Delivery), gửi thư SMTP thực tế qua `nodemailer`,
 * cơ chế thử lại lùi mũ (Exponential Retry Backoff) và chuyển trạng thái sang `DEAD_LETTER` (DLQ).
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEFAULT_BATCH_SIZE = 50;
const BASE_RETRY_DELAY_MS = 2000;
const PROCESSING_LEASE_MS = 5 * 60_000;

export interface OutboxProcessResult {
  processed: number;
  sent: number;
  failed: number;
  deadLettered: number;
}

interface OutboxCandidateRow {
  id: string;
  recipient_id: bigint;
  channel: string;
  notification_type: string;
  title: string;
  body: string;
  payload: unknown;
  status: string;
  attempt_count: number;
  max_attempts: number;
  last_error: string | null;
  created_at: Date;
}

/**
 * Thuật toán: Chiếm giữ nguyên tử lô thông báo bằng CTE `FOR UPDATE SKIP LOCKED` kèm thuê bao hiển thị 5 phút.
 * Khi chạy trên kết nối CSDL thật có `$queryRawUnsafe`, chuyển nguyên tử các dòng ứng viên sang `PROCESSING`
 * để ngăn hai tiến trình Worker gửi trùng email; tự động quay lui về `findMany` cho môi trường mock đơn giản.
 */
async function claimOutboxCandidates(
  database: PrismaClient,
  batchSize: number,
  now: Date,
): Promise<OutboxCandidateRow[]> {
  if (typeof database.$queryRawUnsafe === 'function') {
    // CONFLICT-RESOLVED: Khóa nguyên tử hàng đợi bằng FOR UPDATE SKIP LOCKED + trạng thái PROCESSING tránh gửi đúp giữa nhiều phiên bản Worker.
    const leaseUntil = new Date(now.getTime() + PROCESSING_LEASE_MS);
    const claimed = await database.$queryRawUnsafe<OutboxCandidateRow[]>(
      `WITH claimed AS (
         SELECT id
         FROM notification_outbox
         WHERE status = 'PENDING'
            OR (status IN ('FAILED', 'PROCESSING') AND next_retry_at <= $1)
         ORDER BY created_at ASC
         LIMIT $2
         FOR UPDATE SKIP LOCKED
       )
       UPDATE notification_outbox AS o
       SET status = 'PROCESSING',
           next_retry_at = $3
       FROM claimed
       WHERE o.id = claimed.id
       RETURNING o.*`,
      now,
      batchSize,
      leaseUntil,
    );
    return claimed
      .map((row) => ({
        ...row,
        recipient_id: BigInt(row.recipient_id),
        attempt_count: Number(row.attempt_count),
        max_attempts: Number(row.max_attempts),
        created_at: row.created_at instanceof Date ? row.created_at : new Date(row.created_at),
      }))
      .sort((a, b) => a.created_at.getTime() - b.created_at.getTime());
  }

  return database.notificationOutbox.findMany({
    where: {
      OR: [
        { status: 'PENDING' },
        {
          status: 'FAILED',
          next_retry_at: { lte: now },
        },
      ],
    },
    orderBy: { created_at: 'asc' },
    take: batchSize,
  });
}

/**
 * Processes a batch of pending and retryable notification outbox entries.
 *
 * Thuật toán: Xử lý lô hàng đợi Transactional Outbox có chống trùng lặp lũy đẳng và lùi mũ thử lại (Exponential Backoff).
 * - Pha 1 (Chiếm giữ lô FIFO): Thu thập tối đa `batchSize` bản ghi qua `claimOutboxCandidates` (`FOR UPDATE SKIP LOCKED`).
 * - Pha 2 (Cắt mạch DLQ sớm): Nếu `attempt_count >= max_attempts`, chuyển thẳng bản ghi sang `DEAD_LETTER`.
 * - Pha 3 (Phân phát đa kênh lũy đẳng): Định tuyến theo `channel` (`IN_APP`, `EMAIL`, `BOTH`); với kênh `EMAIL`,
 *   gửi thật qua `nodemailer` khi có `SMTP_HOST` hoặc ném lỗi thật để kích hoạt chu trình thử lại / DLQ trung thực.
 * - Pha 4 (Lùi mũ khi lỗi): Tăng `attempt_count`, đặt lịch `delayMs = BASE_RETRY_DELAY_MS * 2^newAttemptCount` hoặc chuyển sang `DEAD_LETTER`.
 */
export async function processOutboxBatch(options?: {
  databaseClient?: PrismaClient;
  batchSize?: number;
  now?: Date;
  emailSender?: (recipientId: bigint, title: string, body: string) => Promise<boolean>;
}): Promise<OutboxProcessResult> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const batchSize = options?.batchSize ?? DEFAULT_BATCH_SIZE;
  const now = options?.now ?? new Date();

  const candidates = await claimOutboxCandidates(database, batchSize, now);

  const result: OutboxProcessResult = {
    processed: candidates.length,
    sent: 0,
    failed: 0,
    deadLettered: 0,
  };

  for (const item of candidates) {
    if (item.attempt_count >= item.max_attempts) {
      await database.notificationOutbox.update({
        where: { id: item.id },
        data: {
          status: 'DEAD_LETTER',
          last_error: item.last_error ?? 'Exceeded max retry attempts.',
        },
      });
      result.deadLettered++;
      continue;
    }

    try {
      const wantsInApp = item.channel === 'IN_APP' || item.channel === 'BOTH';
      const wantsEmail = item.channel === 'EMAIL' || item.channel === 'BOTH';

      if (!wantsInApp && !wantsEmail) {
        throw new Error(`Unsupported channel: ${item.channel}`);
      }

      if (wantsInApp && typeof database.notification?.create === 'function') {
        const payload = (item.payload as Record<string, unknown>) ?? {};
        const relatedObjectType = payload['relatedObjectType']
          ? String(payload['relatedObjectType'])
          : null;
        const relatedObjectId = payload['relatedObjectId']
          ? String(payload['relatedObjectId'])
          : null;

        // Thuật toán: Khử trùng lặp lũy đẳng (Idempotent Deduplication) trên khóa nghiệp vụ (recipient_id, related_object_type, related_object_id)
        let alreadyDelivered = false;
        if (
          relatedObjectType &&
          relatedObjectId &&
          typeof database.notification.findFirst === 'function'
        ) {
          const existing = await database.notification.findFirst({
            where: {
              recipient_id: item.recipient_id,
              related_object_type: relatedObjectType,
              related_object_id: relatedObjectId,
            },
          });
          if (existing) {
            alreadyDelivered = true;
          }
        }

        if (!alreadyDelivered) {
          await database.notification.create({
            data: {
              id: randomUUID(),
              recipient_id: item.recipient_id,
              notification_type: item.notification_type,
              title: item.title,
              body: item.body,
              status: 'UNREAD' as notification_status,
              related_object_type: relatedObjectType,
              related_object_id: relatedObjectId,
              created_at: now,
            },
          });
        }
      }

      if (wantsEmail) {
        if (options?.emailSender) {
          const success = await options.emailSender(item.recipient_id, item.title, item.body);
          if (!success) throw new Error('External email delivery returned failure.');
        } else if (process.env['SMTP_HOST']?.trim()) {
          await deliverOutboxEmailViaSmtp(database, {
            recipient_id: item.recipient_id,
            title: item.title,
            body: item.body,
            payload: item.payload,
          });
        } else {
          // CONFLICT-RESOLVED: Không đánh dấu giả SENT khi thiếu cấu hình SMTP_HOST; ném lỗi để ghi nhận FAILED / DEAD_LETTER trung thực.
          throw new Error('SMTP transport is not configured (missing SMTP_HOST)');
        }
      }

      await database.notificationOutbox.update({
        where: { id: item.id },
        data: {
          status: 'SENT',
          processed_at: now,
          last_error: null,
        },
      });
      result.sent++;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const newAttemptCount = item.attempt_count + 1;

      if (newAttemptCount >= item.max_attempts) {
        await database.notificationOutbox.update({
          where: { id: item.id },
          data: {
            status: 'DEAD_LETTER',
            attempt_count: newAttemptCount,
            last_error: errorMsg,
          },
        });
        result.deadLettered++;
      } else {
        // Thuật toán: Lùi mũ cấp số nhân (Exponential Retry Backoff): delayMs = BASE_RETRY_DELAY_MS * 2^newAttemptCount
        const delayMs = BASE_RETRY_DELAY_MS * Math.pow(2, newAttemptCount);
        const nextRetry = new Date(now.getTime() + delayMs);

        await database.notificationOutbox.update({
          where: { id: item.id },
          data: {
            status: 'FAILED',
            attempt_count: newAttemptCount,
            next_retry_at: nextRetry,
            last_error: errorMsg,
          },
        });
        result.failed++;
      }
    }
  }

  return result;
}

/**
 * Starts the notification outbox processor background runner.
 *
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler)
 * điều phối tiến trình quét Transactional Outbox và dừng sạch khi nhận `AbortSignal`.
 */
export function startNotificationOutboxJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  let isRunning = false;
  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    if (isRunning) return;
    isRunning = true;

    try {
      const result = await processOutboxBatch();
      if (result.processed > 0) {
        console.info(
          `Notification outbox processed ${result.processed} message(s): ${result.sent} sent, ${result.failed} failed, ${result.deadLettered} DLQ.`,
        );
      }
    } catch (err) {
      console.error(`Notification outbox cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Notification outbox processor stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Notification outbox worker started (interval: ${intervalMs}ms).`);
}
