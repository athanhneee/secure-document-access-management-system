/**
 * Module: Non-Destructive Document Retention Horizon Scanner Helper
 * Thuật toán: Quét Hạn Lưu Trữ Tài Liệu Cô Lập Theo Chủ Sở Hữu & Độ Mật Bell-LaPadula Kèm Chống Xả Rác Kiểm Toán (`BUG-056`).
 *   1. Khi gọi qua HTTP bởi `principal` (`!systemScan`): chỉ quét và trả về tài liệu `ACTIVE`/`ARCHIVED` thuộc sở hữu của chính `principal.userId` (`owner_id: principal.userId`) và thỏa trần độ mật `userClearanceRank >= documentRank`.
 *   2. Khi chạy nền (`systemScan === true` không có `principal`): quét gửi thông báo riêng tới từng chủ sở hữu tài liệu.
 *   3. Chỉ ghi `DOCUMENT_RETENTION_WARNING` vào `audit_logs` cho các mục mới phát sinh cảnh báo/thông báo chưa trùng trong chu kỳ/ngày hiện tại.
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import { isPureTechnicalOrAuditRole } from './document-access-guard.helper.js';
import type { RetentionCheckResult } from './documents.types.js';
import { checkUserClearance } from './pep-clearance.helper.js';
import { hasPrivilegedNonBusinessCapability } from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Quét chân trời lưu trữ không phá hủy kèm cô lập chủ sở hữu + độ mật Bell-LaPadula và khử trùng nhật ký kiểm toán (`BUG-056`).
 */
export async function executeCheckRetentionWarnings(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  realtime?: RealtimeEventsService | undefined;
  daysThreshold: number;
  principal?: AuthPrincipal | undefined;
  context?: RequestContext | undefined;
  systemScan?: boolean | undefined;
}): Promise<RetentionCheckResult> {
  const { database, audit, realtime, daysThreshold, principal, context, systemScan } = params;
  const now = new Date();

  if (!principal && !systemScan) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Authenticated principal is required for retention horizon scan.',
    });
  }
  if (
    principal &&
    (isPureTechnicalOrAuditRole(principal) ||
      (await hasPrivilegedNonBusinessCapability(database, principal, now)))
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Separated privileged roles cannot inspect business document retention.',
    });
  }

  const todayUtcStartMs = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const thresholdDate = new Date(todayUtcStartMs + daysThreshold * 86_400_000);

  const isUserScopedScan = Boolean(principal && !systemScan);
  const candidateDocuments = await database.document.findMany({
    where: {
      status: { in: ['ACTIVE', 'ARCHIVED'] },
      ...(isUserScopedScan && principal ? { owner_id: principal.userId } : {}),
      retention_until: { not: null, lte: thresholdDate },
    },
    include: {
      users: { select: { id: true, username: true } },
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true },
      },
    },
  });

  const expiringDocuments: typeof candidateDocuments = [];
  if (isUserScopedScan && principal) {
    for (const doc of candidateDocuments) {
      if (doc.status !== undefined && doc.status !== 'ACTIVE' && doc.status !== 'ARCHIVED') {
        continue;
      }
      if (doc.owner_id !== principal.userId) {
        continue;
      }
      const docWithClass = doc as typeof doc & {
        classification_history?: Array<{
          classification_levels?: { rank?: number | null } | null;
        }>;
      };
      const docRank = docWithClass.classification_history?.[0]?.classification_levels?.rank ?? 0;
      if (
        docRank > 0 &&
        typeof database?.userAttributeAssignment?.findFirst === 'function' &&
        !(await checkUserClearance(database, principal.userId, docRank, now))
      ) {
        continue;
      }
      expiringDocuments.push(doc);
    }
  } else {
    for (const doc of candidateDocuments) {
      if (doc.status !== undefined && doc.status !== 'ACTIVE' && doc.status !== 'ARCHIVED') {
        continue;
      }
      expiringDocuments.push(doc);
    }
  }

  const warnings: RetentionCheckResult['warnings'] = [];
  const notificationBatch: Array<{
    id: string;
    recipient_id: bigint;
    notification_type: 'RETENTION_EXPIRATION_WARNING';
    title: string;
    body: string;
    related_object_type: 'DOCUMENT';
    related_object_id: string;
    status: 'UNREAD';
  }> = [];
  const securityAlertBatch: Array<{
    id: string;
    alert_type: 'RETENTION_OVERDUE';
    severity: 'MEDIUM';
    status: 'OPEN';
    title: string;
    description: string;
    document_id: string;
    detected_user_id: bigint;
  }> = [];
  const auditItems: Array<{
    doc: (typeof expiringDocuments)[number];
    dateStr: string;
    daysRemaining: number;
  }> = [];

  for (const doc of expiringDocuments) {
    if (!doc.retention_until) continue;
    const retentionUtcStartMs = Date.UTC(
      doc.retention_until.getUTCFullYear(),
      doc.retention_until.getUTCMonth(),
      doc.retention_until.getUTCDate(),
    );
    const daysRemaining = Math.round((retentionUtcStartMs - todayUtcStartMs) / 86_400_000);
    const dateStr = doc.retention_until.toISOString().substring(0, 10);
    const remainingText =
      daysRemaining < 0
        ? 'đã hết hạn'
        : daysRemaining === 0
          ? 'hết hạn trong hôm nay'
          : `còn ${daysRemaining} ngày`;

    notificationBatch.push({
      id: randomUUID(),
      recipient_id: doc.owner_id,
      notification_type: 'RETENTION_EXPIRATION_WARNING',
      title: 'Cảnh báo hạn lưu trữ tài liệu',
      body: `Tài liệu "${doc.title}" (${doc.document_code}) sẽ hết hạn lưu trữ vào ngày ${dateStr} (${remainingText}). Cần xem xét chính sách phê duyệt lưu trữ hoặc tiêu hủy.`,
      related_object_type: 'DOCUMENT',
      related_object_id: doc.id,
      status: 'UNREAD',
    });

    if (daysRemaining < 0) {
      securityAlertBatch.push({
        id: randomUUID(),
        alert_type: 'RETENTION_OVERDUE',
        severity: 'MEDIUM',
        status: 'OPEN',
        title: `Tài liệu quá hạn lưu trữ: ${doc.document_code}`,
        description: `Tài liệu "${doc.title}" (${doc.document_code}) đã quá hạn lưu trữ ngày ${dateStr}. Không tự xóa file khi chưa có chính sách phê duyệt.`,
        document_id: doc.id,
        detected_user_id: doc.owner_id,
      });
    }

    auditItems.push({ doc, dateStr, daysRemaining });
    warnings.push({
      documentId: doc.id,
      documentCode: doc.document_code,
      retentionUntil: dateStr,
      daysRemaining,
    });
  }

  // CONFLICT-RESOLVED: Khử trùng lặp cảnh báo RETENTION_OVERDUE đang OPEN/INVESTIGATING và thông báo chưa đọc hoặc đã phát trong cùng ngày UTC (`BUG-056`).
  let existingOverdueDocIds = new Set<string>();
  if (securityAlertBatch.length > 0 && typeof database.securityAlert?.findMany === 'function') {
    const overdueDocIds = securityAlertBatch.map((a) => a.document_id);
    const existingAlerts = await database.securityAlert.findMany({
      where: {
        alert_type: 'RETENTION_OVERDUE',
        status: { in: ['OPEN', 'INVESTIGATING'] },
        document_id: { in: overdueDocIds },
      },
      select: { document_id: true },
    });
    existingOverdueDocIds = new Set(
      existingAlerts.map((a) => a.document_id).filter((id): id is string => Boolean(id)),
    );
  }
  const deduplicatedAlertBatch = securityAlertBatch.filter(
    (a) => !existingOverdueDocIds.has(a.document_id),
  );

  let existingNotifiedKeys = new Set<string>();
  let existingNotifiedDocIds = new Set<string>();
  if (notificationBatch.length > 0 && typeof database.notification?.findMany === 'function') {
    const existingNotifications = await database.notification.findMany({
      where: {
        notification_type: 'RETENTION_EXPIRATION_WARNING',
        related_object_id: { in: notificationBatch.map((n) => n.related_object_id) },
        OR: [{ status: 'UNREAD' }, { created_at: { gte: new Date(todayUtcStartMs) } }],
      },
      select: { recipient_id: true, related_object_id: true },
    });
    for (const item of existingNotifications) {
      if (!item.related_object_id) continue;
      const recipientId = (item as { recipient_id?: bigint | null }).recipient_id;
      if (recipientId !== undefined && recipientId !== null) {
        existingNotifiedKeys.add(`${recipientId.toString()}:${item.related_object_id}`);
      } else {
        existingNotifiedDocIds.add(item.related_object_id);
      }
    }
  }
  const deduplicatedNotificationBatch = notificationBatch.filter(
    (n) =>
      !existingNotifiedDocIds.has(n.related_object_id) &&
      !existingNotifiedKeys.has(`${n.recipient_id.toString()}:${n.related_object_id}`),
  );

  if (deduplicatedNotificationBatch.length > 0) {
    if (typeof database.notification?.createMany === 'function') {
      await database.notification.createMany({ data: deduplicatedNotificationBatch });
    } else {
      for (const data of deduplicatedNotificationBatch) {
        await database.notification.create({ data });
      }
    }
    const createdAtIso = now.toISOString();
    for (const item of deduplicatedNotificationBatch) {
      realtime?.publish({
        type: 'NOTIFICATION_CREATED',
        targetUserIds: [item.recipient_id.toString()],
        payload: {
          id: item.id,
          notificationType: item.notification_type,
          title: item.title,
          body: item.body,
          relatedObjectType: item.related_object_type,
          relatedObjectId: item.related_object_id,
          status: item.status,
          createdAt: createdAtIso,
          readAt: null,
        },
      });
    }
  }

  if (deduplicatedAlertBatch.length > 0) {
    if (typeof database.securityAlert?.createMany === 'function') {
      await database.securityAlert.createMany({ data: deduplicatedAlertBatch });
    } else {
      for (const data of deduplicatedAlertBatch) {
        await database.securityAlert.create({ data });
      }
    }
  }

  const newlyEmittedDocIds = new Set<string>([
    ...deduplicatedNotificationBatch.map((n) => n.related_object_id),
    ...deduplicatedAlertBatch.map((a) => a.document_id),
  ]);

  const effectiveContext = context ?? {
    ip: '127.0.0.1',
    correlationId: randomUUID(),
    userAgent: 'sda-retention-job/1.0',
  };
  for (const { doc, dateStr, daysRemaining } of auditItems) {
    if (!newlyEmittedDocIds.has(doc.id)) continue;
    await audit.record(
      {
        action: 'DOCUMENT_RETENTION_WARNING',
        outcome: 'SUCCESS',
        actorUserId: principal?.userId ?? doc.owner_id,
        actorUsername: principal?.username ?? doc.users?.username ?? 'system',
        documentId: doc.id,
        details: { documentCode: doc.document_code, retentionUntil: dateStr, daysRemaining },
      },
      effectiveContext,
    );
  }

  return {
    processedCount: expiringDocuments.length,
    warningCount: warnings.length,
    warnings,
  };
}
