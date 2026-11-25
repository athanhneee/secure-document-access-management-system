/**
 * Module: Non-Destructive Document Retention Horizon Scanner Helper
 * Thuật toán: Quét Hạn Lưu Trữ Tài Liệu Gom Lô Khử Truy Vấn `N+1` (`Batch Department RBAC & Bulk Notification/Alert Insert`).
 *   1. Truy vấn một lần tập tài liệu chưa xóa có `retention_until <= now + daysThreshold`.
 *   2. Nếu có `principal`, khử trùng lặp danh sách `department_id` của các tài liệu không thuộc sở hữu trực tiếp và kiểm tra quyền `DOCUMENT:CLASSIFY` song song một lượt.
 *   3. Gom lô toàn bộ thông báo (`notification.createMany`) và cảnh báo quá hạn (`securityAlert.createMany`) để triệt tiêu truy vấn `N+1` vòng lặp,
 *      tự động lùi về `create` tuần tự khi chạy trên đối tượng giả lập kiểm thử đơn vị không cài đặt `createMany`.
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import { isPureTechnicalOrAuditRole } from './document-access-guard.helper.js';
import type { RetentionCheckResult } from './documents.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Quét chân trời lưu trữ không phá hủy kèm gom lô quyền phòng ban, thông báo và cảnh báo an ninh.
 */
export async function executeCheckRetentionWarnings(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  daysThreshold: number;
  principal?: AuthPrincipal | undefined;
  context?: RequestContext | undefined;
  systemScan?: boolean | undefined;
}): Promise<RetentionCheckResult> {
  const { database, authorization, audit, daysThreshold, principal, context, systemScan } = params;
  if (!principal && !systemScan) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Authenticated principal is required for retention horizon scan.',
    });
  }
  if (principal && isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Separated privileged roles cannot inspect business document retention.',
    });
  }
  const now = new Date();
  const todayUtcStartMs = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const thresholdDate = new Date(todayUtcStartMs + daysThreshold * 86_400_000);

  const allExpiringDocuments = await database.document.findMany({
    where: {
      status: { notIn: ['DELETED'] },
      retention_until: { not: null, lte: thresholdDate },
    },
    include: { users: { select: { id: true, username: true } } },
  });

  const expiringDocuments: typeof allExpiringDocuments = [];
  if (principal) {
    const candidateDepts = Array.from(
      new Set(
        allExpiringDocuments
          .filter((doc) => doc.owner_id !== principal.userId)
          .map((doc) => doc.department_id),
      ),
    );
    const deptPermissionEntries = await Promise.all(
      candidateDepts.map(async (deptId) => {
        const allowed = await authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', {
          targetDepartmentId: deptId,
        });
        return [deptId.toString(), allowed] as const;
      }),
    );
    const permittedDepts: Record<string, boolean> = Object.fromEntries(deptPermissionEntries);

    for (const doc of allExpiringDocuments) {
      if (doc.owner_id === principal.userId || permittedDepts[doc.department_id.toString()]) {
        expiringDocuments.push(doc);
      }
    }
  } else {
    expiringDocuments.push(...allExpiringDocuments);
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

  // CONFLICT-RESOLVED: Khử trùng lặp cảnh báo RETENTION_OVERDUE đang OPEN/INVESTIGATING và thông báo chưa đọc cùng ngày (N11).
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

  let existingUnreadDocIds = new Set<string>();
  if (notificationBatch.length > 0 && typeof database.notification?.findMany === 'function') {
    const existingNotifications = await database.notification.findMany({
      where: {
        notification_type: 'RETENTION_EXPIRATION_WARNING',
        status: 'UNREAD',
        related_object_id: { in: notificationBatch.map((n) => n.related_object_id) },
      },
      select: { related_object_id: true },
    });
    existingUnreadDocIds = new Set(
      existingNotifications
        .map((n) => n.related_object_id)
        .filter((id): id is string => Boolean(id)),
    );
  }
  const deduplicatedNotificationBatch = notificationBatch.filter(
    (n) => !existingUnreadDocIds.has(n.related_object_id),
  );

  if (deduplicatedNotificationBatch.length > 0) {
    if (typeof database.notification?.createMany === 'function') {
      await database.notification.createMany({ data: deduplicatedNotificationBatch });
    } else {
      for (const data of deduplicatedNotificationBatch) {
        await database.notification.create({ data });
      }
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

  const effectiveContext = context ?? {
    ip: '127.0.0.1',
    correlationId: randomUUID(),
    userAgent: 'sda-retention-job/1.0',
  };
  for (const { doc, dateStr, daysRemaining } of auditItems) {
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
