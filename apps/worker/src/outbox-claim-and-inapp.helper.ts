import { createHash } from 'node:crypto';
import {
  UniqueConstraintError,
  type getDatabaseClient,
  mapDatabaseError,
  type notification_status,
} from '@sda/database';

/**
 * Thuật toán / Tổng quan module:
 * Trình hỗ trợ chiếm giữ lô thông báo (`FOR UPDATE SKIP LOCKED`) và ghi nhận thông báo trong ứng dụng (`IN_APP`)
 * đảm bảo tính lũy đẳng tuyệt đối (Idempotent Delivery) qua các lần thử lại kênh `BOTH` khi SMTP tạm thời lỗi.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;
const PROCESSING_LEASE_MS = 5 * 60_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export interface OutboxCandidateRow {
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
 * Thuật toán: Sinh mã định danh thông báo tất định 1-1 từ `outboxItem.id` (Deterministic Notification ID Derivation)
 * để mọi lần thử lại cùng một bản ghi Outbox luôn ánh xạ về đúng một khóa chính duy nhất trong bảng `notifications`.
 */
export function deriveDeterministicNotificationId(outboxId: string): string {
  const trimmed = outboxId.trim();
  if (UUID_RE.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  const hex = createHash('sha256').update(`outbox-inapp:${trimmed}`, 'utf8').digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Thuật toán: Chiếm giữ nguyên tử lô thông báo bằng CTE `FOR UPDATE SKIP LOCKED` kèm thuê bao hiển thị 5 phút.
 */
export async function claimOutboxCandidates(
  database: PrismaClient,
  batchSize: number,
  now: Date,
): Promise<OutboxCandidateRow[]> {
  if (typeof database.$queryRawUnsafe === 'function') {
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

export interface DetailedInAppDeliveryResult {
  inAppEnsured: boolean;
  newlyCreated: boolean;
  notificationId: string;
  relatedObjectType: string | null;
  relatedObjectId: string | null;
}

/**
 * Thuật toán: Phân phát thông báo `IN_APP` lũy đẳng đa tầng kèm cờ phân biệt bản ghi mới tạo (`newlyCreated`) với bản ghi đã tồn tại (`BUG-070`):
 * - Tầng 1: Kiểm tra cờ `payload.__inAppDelivered === true` từ lần thử trước của kênh `BOTH` -> `{ inAppEnsured: true, newlyCreated: false }`.
 * - Tầng 2: Kiểm tra sự tồn tại bản ghi theo khóa tất định `id = notificationId` hoặc bộ khóa nghiệp vụ -> `{ inAppEnsured: true, newlyCreated: false }`.
 * - Tầng 3: Chèn mới vào `notifications`; nếu gặp xung đột khóa duy nhất `P2002` thì coi như đã tồn tại (`newlyCreated: false`), tránh bắn lặp SSE `NOTIFICATION_CREATED`.
 */
export async function deliverIdempotentInAppNotificationDetailed(
  database: PrismaClient,
  item: OutboxCandidateRow,
  now: Date,
): Promise<DetailedInAppDeliveryResult> {
  const payloadObj =
    item.payload !== null && typeof item.payload === 'object' && !Array.isArray(item.payload)
      ? (item.payload as Record<string, unknown>)
      : {};

  const notificationId = deriveDeterministicNotificationId(item.id);
  const relatedObjectType = payloadObj['relatedObjectType']
    ? String(payloadObj['relatedObjectType'])
    : null;
  const relatedObjectId = payloadObj['relatedObjectId']
    ? String(payloadObj['relatedObjectId'])
    : null;

  if (typeof database.notification?.create !== 'function') {
    return {
      inAppEnsured: false,
      newlyCreated: false,
      notificationId,
      relatedObjectType,
      relatedObjectId,
    };
  }

  if (payloadObj['__inAppDelivered'] === true) {
    return {
      inAppEnsured: true,
      newlyCreated: false,
      notificationId,
      relatedObjectType,
      relatedObjectId,
    };
  }

  if (typeof database.notification.findFirst === 'function') {
    const existingById = await database.notification.findFirst({
      where: { id: notificationId },
    });
    if (existingById) {
      return {
        inAppEnsured: true,
        newlyCreated: false,
        notificationId: existingById.id ?? notificationId,
        relatedObjectType,
        relatedObjectId,
      };
    }

    const existingByBusinessKey = await database.notification.findFirst({
      where: {
        recipient_id: item.recipient_id,
        notification_type: item.notification_type,
        related_object_id: relatedObjectId,
        ...(relatedObjectType ? { related_object_type: relatedObjectType } : {}),
        ...(relatedObjectId === null ? { title: item.title } : {}),
        created_at: { gte: item.created_at },
      },
    });
    if (existingByBusinessKey) {
      return {
        inAppEnsured: true,
        newlyCreated: false,
        notificationId: existingByBusinessKey.id ?? notificationId,
        relatedObjectType,
        relatedObjectId,
      };
    }
  }

  try {
    await database.notification.create({
      data: {
        id: notificationId,
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
  } catch (err) {
    const code = (err as { code?: string } | null | undefined)?.code;
    if (code === 'P2002' || mapDatabaseError(err) instanceof UniqueConstraintError) {
      return {
        inAppEnsured: true,
        newlyCreated: false,
        notificationId,
        relatedObjectType,
        relatedObjectId,
      };
    }
    throw err;
  }

  return {
    inAppEnsured: true,
    newlyCreated: true,
    notificationId,
    relatedObjectType,
    relatedObjectId,
  };
}

/**
 * Thuật toán: Bao bọc tương thích ngược trả kết quả boolean `inAppEnsured` cho các trình gọi/kiểm thử hiện hữu (`BUG-070`).
 */
export async function deliverIdempotentInAppNotification(
  database: PrismaClient,
  item: OutboxCandidateRow,
  now: Date,
): Promise<boolean> {
  const outcome = await deliverIdempotentInAppNotificationDetailed(database, item, now);
  return outcome.inAppEnsured;
}
