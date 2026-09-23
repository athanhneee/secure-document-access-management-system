import { Injectable, NotFoundException, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type QueryNotificationsInput } from '@sda/contracts';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SendNotificationOptions {
  recipientId: bigint;
  notificationType: string;
  title: string;
  body: string;
  relatedObjectType?: string;
  relatedObjectId?: string;
  channel?: 'IN_APP' | 'EMAIL' | 'BOTH';
  deduplicationKey?: string;
  payload?: Record<string, unknown>;
}

export interface SendNotificationResult {
  notificationId?: string | undefined;
  outboxId?: string | undefined;
  isDuplicate: boolean;
}

export interface OutboxProcessResult {
  processed: number;
  delivered: number;
  retried: number;
  deadLettered: number;
}

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);
  private readonly database: PrismaClient;

  constructor(@Optional() databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Sends in-app notification and queues transactional outbox entry for email/push.
   * Enforces deduplication via deduplication_key.
   */
  async sendNotification(options: SendNotificationOptions): Promise<SendNotificationResult> {
    const channel = options.channel ?? 'BOTH';
    const dedupKey =
      options.deduplicationKey ??
      `${options.notificationType}:${options.recipientId}:${options.relatedObjectType ?? 'none'}:${options.relatedObjectId ?? 'none'}`;

    let notificationId: string | undefined;
    let outboxId: string | undefined;
    let isDuplicate = false;

    // In-App Notification creation
    if (channel === 'IN_APP' || channel === 'BOTH') {
      notificationId = randomUUID();
      try {
        await this.database.notification.create({
          data: {
            id: notificationId,
            recipient_id: options.recipientId,
            notification_type: options.notificationType,
            title: options.title,
            body: options.body,
            related_object_type: options.relatedObjectType ?? null,
            related_object_id: options.relatedObjectId ?? null,
            status: 'UNREAD',
          },
        });
      } catch (err) {
        this.logger.warn(`Failed to create in-app notification:`, err);
      }
    }

    // Outbox queue for Email / external delivery
    if (channel === 'EMAIL' || channel === 'BOTH') {
      try {
        // Check deduplication
        const existingOutbox = await this.database.notificationOutbox.findUnique({
          where: { deduplication_key: dedupKey },
        });

        if (existingOutbox) {
          isDuplicate = true;
          this.logger.log(
            `Notification outbox suppressed duplicate key: ${dedupKey} (current status: ${existingOutbox.status})`,
          );
          outboxId = existingOutbox.id;
        } else {
          outboxId = randomUUID();
          await this.database.notificationOutbox.create({
            data: {
              id: outboxId,
              recipient_id: options.recipientId,
              channel: 'EMAIL',
              notification_type: options.notificationType,
              title: options.title,
              body: options.body,
              payload: (options.payload ?? {}) as never,
              deduplication_key: dedupKey,
              status: 'PENDING',
              attempt_count: 0,
              max_attempts: 5,
              next_retry_at: new Date(),
            },
          });
        }
      } catch (err) {
        // Unique constraint violation also represents duplicate
        isDuplicate = true;
        this.logger.warn(`Outbox insert handled duplicate key ${dedupKey}:`, err);
      }
    }

    return { notificationId, outboxId, isDuplicate };
  }

  /**
   * Retrieves in-app notifications for a user.
   */
  async listUserNotifications(
    userId: bigint,
    query: QueryNotificationsInput,
  ): Promise<{
    data: Array<{
      id: string;
      notificationType: string;
      title: string;
      body: string;
      relatedObjectType: string | null;
      relatedObjectId: string | null;
      status: string;
      createdAt: string;
      readAt: string | null;
    }>;
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
    const where: import('@sda/database').Prisma.NotificationWhereInput = {
      recipient_id: userId,
      ...(query.status ? { status: query.status } : {}),
    };

    const take = query.pageSize + 1;
    const skip = (query.page - 1) * query.pageSize;

    const items = await this.database.notification.findMany({
      where,
      orderBy: { created_at: 'desc' },
      take,
      skip,
    });

    const hasMore = items.length > query.pageSize;
    const resultItems = hasMore ? items.slice(0, query.pageSize) : items;

    return {
      data: resultItems.map((n) => ({
        id: n.id,
        notificationType: n.notification_type,
        title: n.title,
        body: n.body,
        relatedObjectType: n.related_object_type,
        relatedObjectId: n.related_object_id,
        status: n.status,
        createdAt: n.created_at.toISOString(),
        readAt: n.read_at?.toISOString() ?? null,
      })),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

  /**
   * Marks a notification as read (updates status to READ and sets read_at).
   */
  async markAsRead(notificationId: string, userId: bigint): Promise<void> {
    const item = await this.database.notification.findFirst({
      where: { id: notificationId, recipient_id: userId },
    });

    if (!item) {
      throw new NotFoundException({
        errorCode: AppErrorCode.NOTIFICATION_NOT_FOUND,
        message: `Notification ${notificationId} was not found.`,
      });
    }

    if (item.status === 'UNREAD') {
      await this.database.notification.update({
        where: { id: notificationId },
        data: {
          status: 'READ',
          read_at: new Date(),
        },
      });
    }
  }

  /**
   * Processes a batch of pending outbox messages with exponential backoff and DLQ.
   */
  async processOutboxBatch(
    batchSize = 50,
    transportSimulator?: (item: {
      id: string;
      recipient_id: bigint;
      channel: string;
      notification_type: string;
      title: string;
      body: string;
    }) => Promise<boolean>,
  ): Promise<OutboxProcessResult> {
    const now = new Date();
    const pendingItems = await this.database.notificationOutbox.findMany({
      where: {
        status: 'PENDING',
        next_retry_at: { lte: now },
      },
      take: batchSize,
      orderBy: { next_retry_at: 'asc' },
    });

    let delivered = 0;
    let retried = 0;
    let deadLettered = 0;

    for (const item of pendingItems) {
      try {
        // Dispatch via transport (email service / mock simulator)
        const success = transportSimulator ? await transportSimulator(item) : true; // Default simulated success

        if (success) {
          await this.database.notificationOutbox.update({
            where: { id: item.id },
            data: {
              status: 'DELIVERED',
              processed_at: new Date(),
            },
          });
          delivered++;
        } else {
          throw new Error('Transport simulation returned delivery failure.');
        }
      } catch (err) {
        const nextAttempt = item.attempt_count + 1;
        const errorMessage = err instanceof Error ? err.message : String(err);

        if (nextAttempt >= item.max_attempts) {
          // Dead-Letter Queue (DLQ)
          await this.database.notificationOutbox.update({
            where: { id: item.id },
            data: {
              status: 'DEAD_LETTER',
              attempt_count: nextAttempt,
              last_error: errorMessage,
              processed_at: new Date(),
            },
          });
          deadLettered++;
          this.logger.error(
            `Notification ${item.id} moved to DEAD_LETTER after ${nextAttempt} attempts. Error: ${errorMessage}`,
          );
        } else {
          // Exponential backoff: base 1000ms * 2^(attempt)
          const backoffDelayMs = 1000 * Math.pow(2, nextAttempt);
          const nextRetryAt = new Date(Date.now() + backoffDelayMs);

          await this.database.notificationOutbox.update({
            where: { id: item.id },
            data: {
              attempt_count: nextAttempt,
              next_retry_at: nextRetryAt,
              last_error: errorMessage,
            },
          });
          retried++;
          this.logger.warn(
            `Notification ${item.id} retry scheduled in ${backoffDelayMs}ms (attempt #${nextAttempt}).`,
          );
        }
      }
    }

    return {
      processed: pendingItems.length,
      delivered,
      retried,
      deadLettered,
    };
  }
}
