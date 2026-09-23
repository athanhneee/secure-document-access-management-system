import { getDatabaseClient, type notification_status } from '@sda/database';
import { randomUUID } from 'node:crypto';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEFAULT_BATCH_SIZE = 50;
const BASE_RETRY_DELAY_MS = 2000;

export interface OutboxProcessResult {
  processed: number;
  sent: number;
  failed: number;
  deadLettered: number;
}

/**
 * Processes a batch of pending and retryable notification outbox entries.
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

  // Find candidate outbox messages
  const candidates = await database.notificationOutbox.findMany({
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
      if (item.channel === 'IN_APP') {
        const payload = (item.payload as Record<string, unknown>) ?? {};
        const relatedObjectType = payload['relatedObjectType']
          ? String(payload['relatedObjectType'])
          : null;
        const relatedObjectId = payload['relatedObjectId']
          ? String(payload['relatedObjectId'])
          : null;

        // Idempotency: verify if already inserted into notifications
        let alreadyDelivered = false;
        if (relatedObjectType && relatedObjectId) {
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

        await database.notificationOutbox.update({
          where: { id: item.id },
          data: {
            status: 'SENT',
            processed_at: now,
            last_error: null,
          },
        });
        result.sent++;
      } else if (item.channel === 'EMAIL' || item.channel === 'BOTH') {
        // Send email via provider or injected sender
        if (options?.emailSender) {
          const success = await options.emailSender(item.recipient_id, item.title, item.body);
          if (!success) throw new Error('External email delivery returned failure.');
        } else {
          // Standard simulated delivery
          console.info(
            `[Email Dispatch] To recipient ID: ${item.recipient_id} | Title: ${item.title}`,
          );
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
      } else {
        throw new Error(`Unsupported channel: ${item.channel}`);
      }
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
        // Exponential backoff: base * 2^(attempt_count)
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
 */
export function startNotificationOutboxJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }

    try {
      const result = await processOutboxBatch();
      if (result.processed > 0) {
        console.info(
          `Notification outbox processed ${result.processed} message(s): ${result.sent} sent, ${result.failed} failed, ${result.deadLettered} DLQ.`,
        );
      }
    } catch (err) {
      console.error(`Notification outbox cycle failed: ${err}`);
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
