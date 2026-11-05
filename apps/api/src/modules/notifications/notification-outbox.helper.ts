/**
 * Module: NotificationOutboxHelper — Hộp thư đi giao dịch lũy đẳng (Idempotent Transactional Outbox) chống gửi trùng lặp.
 */
import { randomUUID } from 'node:crypto';
import type { Logger } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Đưa thông báo vào hàng đợi Outbox lũy đẳng chống trùng lặp (Idempotent Outbox Enqueue)
 * Mục đích: Đảm bảo mỗi sự kiện nghiệp vụ chỉ sinh tối đa một bản ghi gửi thư tương ứng với `dedupKey` ngay cả dưới điều kiện tranh chấp đồng thời.
 * Cơ chế hoạt động:
 *   - Kiểm tra trước khóa duy nhất `deduplication_key`; nếu đã tồn tại hoặc gặp xung đột ràng buộc duy nhất khi `create`, trả về `isDuplicate: true` thay vì làm hỏng luồng gọi.
 *
 * Algorithm: Idempotent Transactional Outbox Enqueue.
 * Checks deduplication_key uniqueness before inserting a PENDING outbox record;
 * treats unique-constraint collisions as idempotent duplicate suppressions.
 */
export async function enqueueNotificationOutbox(
  database: PrismaClient,
  logger: Logger,
  params: {
    recipientId: bigint;
    notificationType: string;
    title: string;
    body: string;
    payload?: Record<string, unknown>;
    dedupKey: string;
  },
): Promise<{ outboxId?: string | undefined; isDuplicate: boolean }> {
  try {
    const existingOutbox = await database.notificationOutbox.findUnique({
      where: { deduplication_key: params.dedupKey },
    });

    if (existingOutbox) {
      logger.log(
        `Notification outbox suppressed duplicate key: ${params.dedupKey} (current status: ${existingOutbox.status})`,
      );
      return { outboxId: existingOutbox.id, isDuplicate: true };
    }

    const outboxId = randomUUID();
    await database.notificationOutbox.create({
      data: {
        id: outboxId,
        recipient_id: params.recipientId,
        channel: 'EMAIL',
        notification_type: params.notificationType,
        title: params.title,
        body: params.body,
        payload: (params.payload ?? {}) as never,
        deduplication_key: params.dedupKey,
        status: 'PENDING',
        attempt_count: 0,
        max_attempts: 5,
        next_retry_at: new Date(),
      },
    });
    return { outboxId, isDuplicate: false };
  } catch (err) {
    logger.warn(`Outbox insert handled duplicate key ${params.dedupKey}:`, err);
    return { outboxId: undefined, isDuplicate: true };
  }
}
