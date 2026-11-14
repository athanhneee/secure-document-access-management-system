import { getDatabaseClient, type Prisma } from '@sda/database';
import {
  claimOutboxCandidates,
  deliverIdempotentInAppNotification,
} from './outbox-claim-and-inapp.helper.js';
import { deliverOutboxEmailViaSmtp } from './outbox-mailer.helper.js';
import { incrementOutboxDeadLetter, recordWorkerJobRun } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ xử lý hàng đợi thông báo theo mẫu Transactional Outbox kết hợp phân phát lũy đẳng kênh `BOTH`
 * (không bao giờ nhân bản thông báo `IN_APP` khi SMTP thử lại), gửi thư SMTP thực tế qua `nodemailer`,
 * thử lại lùi mũ (Exponential Retry Backoff) và cập nhật bộ đếm Prometheus DLQ (`sda_worker_outbox_dead_letter_total`).
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEFAULT_BATCH_SIZE = 50;
const BASE_RETRY_DELAY_MS = 2000;

export interface OutboxProcessResult {
  processed: number;
  sent: number;
  failed: number;
  deadLettered: number;
}

function mergeInAppDeliveredFlag(rawPayload: unknown): Prisma.InputJsonValue {
  const base =
    rawPayload !== null && typeof rawPayload === 'object' && !Array.isArray(rawPayload)
      ? { ...(rawPayload as Record<string, unknown>) }
      : {};
  base['__inAppDelivered'] = true;
  return base as Prisma.InputJsonValue;
}

/**
 * Thuật toán: Xử lý lô hàng đợi Transactional Outbox có chống trùng lặp lũy đẳng kênh `BOTH` và lùi mũ thử lại.
 * - Chiếm giữ tối đa `batchSize` bản ghi qua `claimOutboxCandidates` (`FOR UPDATE SKIP LOCKED`).
 * - Với kênh `BOTH`, đánh dấu `inAppDelivered` để nếu nhánh SMTP ném ngoại lệ, lần thử lại kế tiếp chỉ gửi lại email.
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
      incrementOutboxDeadLetter(1);
      continue;
    }

    let inAppDelivered = false;
    try {
      const wantsInApp = item.channel === 'IN_APP' || item.channel === 'BOTH';
      const wantsEmail = item.channel === 'EMAIL' || item.channel === 'BOTH';

      if (!wantsInApp && !wantsEmail) {
        throw new Error(`Unsupported channel: ${item.channel}`);
      }

      if (wantsInApp) {
        inAppDelivered = await deliverIdempotentInAppNotification(database, item, now);
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
          throw new Error('SMTP transport is not configured (missing SMTP_HOST)');
        }
      }

      await database.notificationOutbox.update({
        where: { id: item.id },
        data: {
          status: 'SENT',
          processed_at: now,
          last_error: null,
          ...(inAppDelivered && item.channel === 'BOTH'
            ? { payload: mergeInAppDeliveredFlag(item.payload) }
            : {}),
        },
      });
      result.sent++;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const newAttemptCount = item.attempt_count + 1;
      const updatedPayloadPatch =
        inAppDelivered && item.channel === 'BOTH'
          ? { payload: mergeInAppDeliveredFlag(item.payload) }
          : {};

      if (newAttemptCount >= item.max_attempts) {
        await database.notificationOutbox.update({
          where: { id: item.id },
          data: {
            status: 'DEAD_LETTER',
            attempt_count: newAttemptCount,
            last_error: errorMsg,
            ...updatedPayloadPatch,
          },
        });
        result.deadLettered++;
        incrementOutboxDeadLetter(1);
      } else {
        const delayMs = BASE_RETRY_DELAY_MS * Math.pow(2, newAttemptCount);
        const nextRetry = new Date(now.getTime() + delayMs);

        await database.notificationOutbox.update({
          where: { id: item.id },
          data: {
            status: 'FAILED',
            attempt_count: newAttemptCount,
            next_retry_at: nextRetry,
            last_error: errorMsg,
            ...updatedPayloadPatch,
          },
        });
        result.failed++;
      }
    }
  }

  return result;
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `NotificationOutboxJob`.
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
      recordWorkerJobRun('notification_outbox', 'success');
      if (result.processed > 0) {
        console.info(
          `Notification outbox processed ${result.processed} message(s): ${result.sent} sent, ${result.failed} failed, ${result.deadLettered} DLQ.`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('notification_outbox', 'error');
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
