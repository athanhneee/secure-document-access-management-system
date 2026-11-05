/**
 * Module: DetectionEvaluators — Bộ hàm đánh giá 6 giải thuật tương quan cửa sổ trượt phát hiện xâm nhập (Sliding-Window Event Correlation Evaluators).
 */
import {
  SECURITY_DETECTION_ACTIONS,
  groupAuditLogsByActor,
  isOffHoursTimestampUtc,
  isUntrustedAuditEvent,
} from '@sda/contracts';
import type { getDatabaseClient } from '@sda/database';
import type { DetectionResult, DetectionRule } from './detection-rule-defaults.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AlertMatchCandidate {
  rule: DetectionRule;
  userId?: bigint | null | undefined;
  documentId?: string | null | undefined;
  matchingLogIds: bigint[];
  title: string;
  description: string;
}

/**
 * Thuật toán: Bộ đánh giá tương quan sự kiện cửa sổ trượt đa quy tắc (Unified Sliding-Window Intrusion Rule Evaluator)
 * Mục đích: Phân tích dòng nhật ký `audit_logs` trong đoạn `[now - windowMinutes, now]` theo 6 mô hình tấn công và gọi callback `onMatch` khi đạt ngưỡng `rule.threshold`.
 * Cơ chế hoạt động:
 *   - Tính mốc đầu cửa sổ `windowStart = Date.now() - windowMinutes * 60_000`.
 *   - Phân nhánh theo `rule.ruleCode`, gom cụm sự kiện theo định danh tác nhân (`groupAuditLogsByActor`) và nhóm ẩn danh (`actor_user_id == null` khi áp dụng).
 *   - Chuyển danh sách `audit_log.id` vượt ngưỡng cho `onMatch` để tạo cảnh báo hoặc khử trùng lặp cooldown.
 *
 * Algorithm: Unified Sliding-Window Intrusion Rule Evaluator.
 * Queries `audit_logs` within `[now - windowMinutes, now]` using canonical action sets from
 * `@sda/contracts`, buckets events per actor (plus unattributed system events where applicable),
 * and invokes `onMatch` when event counts reach `rule.threshold`.
 */
export async function evaluateSlidingWindowRule(
  database: PrismaClient,
  rule: DetectionRule,
  windowMinutes: number,
  onMatch: (candidate: AlertMatchCandidate) => Promise<DetectionResult>,
): Promise<DetectionResult[]> {
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
  const results: DetectionResult[] = [];

  // CONFLICT-RESOLVED: Đồng bộ hoàn toàn tập sự kiện audit_logs.action và logic gom nhóm/ngưỡng giữa API và Worker qua SECURITY_DETECTION_ACTIONS trong @sda/contracts.
  switch (rule.ruleCode) {
    case 'MASS_DOWNLOAD': {
      // Thuật toán 1/6 (Mass Download / Data Exfiltration Correlation): Gom cụm sự kiện tải tài liệu thành công theo `actor_user_id` trong cửa sổ trượt.
      const logs = await database.auditLog.findMany({
        where: {
          action: { in: [...SECURITY_DETECTION_ACTIONS.MASS_DOWNLOAD] },
          outcome: 'SUCCESS',
          occurred_at: { gte: windowStart },
          actor_user_id: { not: null },
        },
        select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      for (const [uid, userLogs] of groupAuditLogsByActor(logs).entries()) {
        if (userLogs.length >= rule.threshold) {
          results.push(
            await onMatch({
              rule,
              userId: BigInt(uid),
              documentId: userLogs[0]?.document_id ?? undefined,
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Phát hiện tải hàng loạt: Người dùng #${uid} đã tải ${userLogs.length} tài liệu trong ${windowMinutes} phút`,
              description: `Người dùng ID ${uid} đã thực hiện ${userLogs.length} lần tải tài liệu trong cửa sổ ${windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
            }),
          );
        }
      }
      break;
    }

    case 'REPEATED_DENIED': {
      // Thuật toán 2/6 (Repeated Access Denied / Brute-Force & Privilege Escalation Probing): Đếm số sự kiện `outcome = 'DENIED'` theo từng tác nhân trong cửa sổ trượt.
      const logs = await database.auditLog.findMany({
        where: {
          outcome: 'DENIED',
          occurred_at: { gte: windowStart },
          actor_user_id: { not: null },
        },
        select: { id: true, actor_user_id: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      for (const [uid, userLogs] of groupAuditLogsByActor(logs).entries()) {
        if (userLogs.length >= rule.threshold) {
          results.push(
            await onMatch({
              rule,
              userId: BigInt(uid),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Nhiều lần bị từ chối truy cập: Người dùng #${uid} bị từ chối ${userLogs.length} lần`,
              description: `Người dùng ID ${uid} đã nhận ${userLogs.length} kết quả DENIED trong cửa sổ ${windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
            }),
          );
        }
      }
      break;
    }

    case 'OFF_HOURS_ACCESS': {
      // Thuật toán 3/6 (Off-Hours Temporal Anomaly Detection): Lọc các lượt truy cập tài liệu rơi ngoài khung giờ làm việc chuẩn (`isOffHoursTimestampUtc`) và gom cụm theo người dùng.
      const logs = await database.auditLog.findMany({
        where: {
          action: { in: [...SECURITY_DETECTION_ACTIONS.OFF_HOURS_ACCESS] },
          occurred_at: { gte: windowStart },
          actor_user_id: { not: null },
        },
        select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      const offHoursLogs = logs.filter((log) =>
        isOffHoursTimestampUtc(log.occurred_at, rule.parameters),
      );
      for (const [uid, userLogs] of groupAuditLogsByActor(offHoursLogs).entries()) {
        if (userLogs.length >= rule.threshold) {
          results.push(
            await onMatch({
              rule,
              userId: BigInt(uid),
              documentId: userLogs[0]?.document_id ?? undefined,
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Truy cập ngoài giờ: Người dùng #${uid} truy cập tài liệu mật ngoài khung giờ làm việc`,
              description: `Phát hiện ${userLogs.length} lượt truy cập tài liệu ngoài giờ làm việc bởi người dùng #${uid}.`,
            }),
          );
        }
      }
      break;
    }

    case 'UNTRUSTED_CONTEXT': {
      // Thuật toán 4/6 (Untrusted Network/Device Context & Anonymous Probing): Đánh giá vị từ `isUntrustedAuditEvent` trên cả hai nhánh tác nhân định danh và luồng ẩn danh (`actor_user_id == null`).
      const logs = await database.auditLog.findMany({
        where: { occurred_at: { gte: windowStart } },
        select: { id: true, actor_user_id: true, action: true, details: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      const untrustedLogs = logs.filter((log) => isUntrustedAuditEvent(log.action, log.details));
      for (const [uid, userLogs] of groupAuditLogsByActor(untrustedLogs).entries()) {
        if (userLogs.length >= rule.threshold) {
          results.push(
            await onMatch({
              rule,
              userId: BigInt(uid),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Ngữ cảnh chưa tin cậy: Người dùng #${uid} truy cập từ IP/thiết bị lạ`,
              description: `Phát hiện truy cập từ thiết bị hoặc mạng chưa xác thực (${userLogs.length} lần) bởi người dùng #${uid}.`,
            }),
          );
        }
      }
      const unattributed = untrustedLogs.filter((l) => l.actor_user_id == null);
      if (unattributed.length >= rule.threshold) {
        results.push(
          await onMatch({
            rule,
            matchingLogIds: unattributed.map((l) => l.id),
            title: 'Ngữ cảnh chưa tin cậy: Phát hiện truy cập ẩn danh từ IP/thiết bị lạ',
            description: `Phát hiện ${unattributed.length} lượt truy cập chưa định danh từ thiết bị hoặc mạng chưa xác thực.`,
          }),
        );
      }
      break;
    }

    case 'REFRESH_TOKEN_REUSE': {
      // Thuật toán 5/6 (Revoked/Rotated Session Token Replay Detection): Tương quan nỗ lực phát lại thẻ phiên làm mới đã thu hồi/xoay vòng cho cả người dùng định danh và luồng ẩn danh.
      const logs = await database.auditLog.findMany({
        where: {
          action: { in: [...SECURITY_DETECTION_ACTIONS.REFRESH_TOKEN_REUSE] },
          occurred_at: { gte: windowStart },
        },
        select: { id: true, actor_user_id: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      for (const [uid, userLogs] of groupAuditLogsByActor(logs).entries()) {
        if (userLogs.length >= rule.threshold) {
          results.push(
            await onMatch({
              rule,
              userId: BigInt(uid),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Tái sử dụng Refresh Token: Người dùng #${uid}`,
              description: `Phát hiện việc sử dụng lại refresh token đã bị thu hồi/rotate bởi người dùng #${uid}.`,
            }),
          );
        }
      }
      const unattributed = logs.filter((l) => l.actor_user_id == null);
      if (unattributed.length >= rule.threshold) {
        results.push(
          await onMatch({
            rule,
            matchingLogIds: unattributed.map((l) => l.id),
            title: 'Tái sử dụng Refresh Token đã thu hồi',
            description: `Phát hiện ${unattributed.length} nỗ lực sử dụng lại refresh token đã xoay vòng hoặc thu hồi.`,
          }),
        );
      }
      break;
    }

    case 'AUDIT_INTEGRITY_COMPROMISED': {
      // Thuật toán 6/6 (Cryptographic Audit Hash-Chain Tamper Detection): Phát hiện sai lệch chữ ký HMAC hoặc đứt gãy chuỗi băm kiểm toán toàn hệ thống trong cửa sổ trượt.
      const logs = await database.auditLog.findMany({
        where: {
          action: { in: [...SECURITY_DETECTION_ACTIONS.AUDIT_INTEGRITY_COMPROMISED] },
          occurred_at: { gte: windowStart },
        },
        select: { id: true, actor_user_id: true, occurred_at: true },
        orderBy: { occurred_at: 'desc' },
      });
      if (logs.length >= rule.threshold) {
        results.push(
          await onMatch({
            rule,
            userId: logs[0]?.actor_user_id ?? undefined,
            matchingLogIds: logs.map((l) => l.id),
            title: 'CRITICAL: Tính toàn vẹn của chuỗi kiểm toán bị xâm phạm',
            description: `Hệ thống ghi nhận ${logs.length} sự kiện vi phạm hoặc chỉnh sửa trái phép chuỗi HMAC kiểm toán.`,
          }),
        );
      }
      break;
    }
  }

  return results;
}
