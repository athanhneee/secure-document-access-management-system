/**
 * Module: Non-Destructive Document Retention Horizon Scanner Helper
 * Algorithm: Scans non-deleted documents with `retention_until <= now + daysThreshold`, filters by caller
 *   ownership or `DOCUMENT:CLASSIFY` department permission, emits owner notifications, and raises `RETENTION_OVERDUE` alerts.
 */
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import type { RetentionCheckResult } from './documents.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Non-Destructive Retention Horizon Scan
 * Identifies non-deleted documents with `retention_until <= now + daysThreshold`, notifying owners and raising `RETENTION_OVERDUE` alerts.
 */
export async function executeCheckRetentionWarnings(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  daysThreshold: number;
  principal?: AuthPrincipal | undefined;
  context?: RequestContext | undefined;
}): Promise<RetentionCheckResult> {
  const { database, authorization, audit, daysThreshold, principal, context } = params;
  const now = new Date();
  const thresholdDate = new Date(now.getTime() + daysThreshold * 86400 * 1000);

  const allExpiringDocuments = await database.document.findMany({
    where: {
      status: { notIn: ['DELETED'] },
      retention_until: { not: null, lte: thresholdDate },
    },
    include: { users: { select: { id: true, username: true } } },
  });

  const expiringDocuments: typeof allExpiringDocuments = [];
  if (principal) {
    for (const doc of allExpiringDocuments) {
      if (doc.owner_id === principal.userId) {
        expiringDocuments.push(doc);
        continue;
      }
      const canClassifyDept = await authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', {
        targetDepartmentId: doc.department_id,
      });
      if (canClassifyDept) expiringDocuments.push(doc);
    }
  } else {
    expiringDocuments.push(...allExpiringDocuments);
  }

  const warnings: RetentionCheckResult['warnings'] = [];

  for (const doc of expiringDocuments) {
    if (!doc.retention_until) continue;
    const daysRemaining = Math.ceil((doc.retention_until.getTime() - now.getTime()) / 86_400_000);
    const dateStr = doc.retention_until.toISOString().substring(0, 10);

    await database.notification.create({
      data: {
        id: randomUUID(),
        recipient_id: doc.owner_id,
        notification_type: 'RETENTION_EXPIRATION_WARNING',
        title: 'Cảnh báo hạn lưu trữ tài liệu',
        body: `Tài liệu "${doc.title}" (${doc.document_code}) sẽ hết hạn lưu trữ vào ngày ${dateStr} (${daysRemaining <= 0 ? 'đã hết hạn' : `còn ${daysRemaining} ngày`}). Cần xem xét chính sách phê duyệt lưu trữ hoặc tiêu hủy.`,
        related_object_type: 'DOCUMENT',
        related_object_id: doc.id,
        status: 'UNREAD',
      },
    });

    if (daysRemaining <= 0) {
      await database.securityAlert.create({
        data: {
          id: randomUUID(),
          alert_type: 'RETENTION_OVERDUE',
          severity: 'MEDIUM',
          status: 'OPEN',
          title: `Tài liệu quá hạn lưu trữ: ${doc.document_code}`,
          description: `Tài liệu "${doc.title}" (${doc.document_code}) đã quá hạn lưu trữ ngày ${dateStr}. Không tự xóa file khi chưa có chính sách phê duyệt.`,
          document_id: doc.id,
          detected_user_id: doc.owner_id,
        },
      });
    }

    await audit.record(
      {
        action: 'DOCUMENT_RETENTION_WARNING',
        outcome: 'SUCCESS',
        actorUserId: principal?.userId ?? doc.owner_id,
        actorUsername: principal?.username ?? doc.users?.username ?? 'system',
        documentId: doc.id,
        details: { documentCode: doc.document_code, retentionUntil: dateStr, daysRemaining },
      },
      context ?? {
        ip: '127.0.0.1',
        correlationId: randomUUID(),
        userAgent: 'sda-retention-job/1.0',
      },
    );

    warnings.push({
      documentId: doc.id,
      documentCode: doc.document_code,
      retentionUntil: dateStr,
      daysRemaining,
    });
  }

  return {
    processedCount: expiringDocuments.length,
    warningCount: warnings.length,
    warnings,
  };
}
