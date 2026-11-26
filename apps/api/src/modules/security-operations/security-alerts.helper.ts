/**
 * @module SecurityAlertsHelper
 * Thuật toán: Xây dựng vị từ lọc cảnh báo đa tiêu chí, kiểm chứng máy trạng thái hữu hạn của cảnh báo SOC
 * (`VALID_ALERT_TRANSITIONS`), cưỡng chế ghi chú giải trình tối thiểu 5 ký tự khi đóng cảnh báo và ánh xạ DTO chi tiết.
 */
import { BadRequestException } from '@nestjs/common';
import type { Prisma, alert_status, severity_level } from '@sda/database';
import {
  AppErrorCode,
  type QuerySecurityAlertsInput,
  type UpdateAlertStatusInput,
} from '@sda/contracts';

export interface AlertNoteDto {
  id: string;
  authorName: string;
  note: string;
  createdAt: string;
}

export interface AlertDetail {
  id: string;
  alertType: string;
  severity: severity_level;
  status: alert_status;
  title: string;
  description: string;
  ipAddress: string | null;
  notes: AlertNoteDto[];
  detectedUserId: string | null;
  detectedUser?: {
    id: string;
    username: string;
    fullName: string;
    employeeCode: string | null;
  } | null;
  documentId: string | null;
  detectedAt: string;
  assignedTo: string | null;
  assignedToUser?: {
    id: string;
    username: string;
    fullName: string;
  } | null;
  resolvedAt: string | null;
  resolutionNote: string | null;
  linkedAuditLogsCount: number;
  linkedAuditLogs?: Array<{
    id: string;
    action: string;
    occurredAt: string;
    outcome: string;
    ipAddress: string | null;
  }>;
  incidentReports?: Array<{
    id: string;
    incidentCode: string;
    title: string;
    status: string;
    createdAt: string;
  }>;
}

const APPENDED_NOTE_LINE_RE =
  /^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\]\s+([^\s:]+):\s*(.*)$/u;
const IPV4_EXTRACT_RE = /\b((?:\d{1,3}\.){3}\d{1,3})\b/u;

/**
 * Thuật toán: Tách Bạch Mô Tả Kỹ Thuật Gốc & Nhật Ký Ghi Chú Điều Tra Có Cấu Trúc (`parseAlertDescriptionAndNotes`)
 * Mục đích: Khôi phục đầy đủ danh sách ghi chú điều tra đã nối bằng `POST /security-alerts/:id/notes` (`[ISO-8601] username: nội dung`)
 *   sang mảng `notes[]` tường minh mà vẫn bảo toàn nguyên vẹn phần mô tả gốc `description` (không cắt nhầm thẻ `[Network DLP]` hay `[BLOCKED]`) (#01, #02).
 */
export function parseAlertDescriptionAndNotes(
  rawDescription: string | null | undefined,
  alertId = '',
): { baseDescription: string; notes: AlertNoteDto[] } {
  const source = rawDescription ?? '';
  if (!source) return { baseDescription: '', notes: [] };

  const lines = source.split(/\r?\n/u);
  const baseLines: string[] = [];
  const notes: AlertNoteDto[] = [];

  for (const line of lines) {
    const match = APPENDED_NOTE_LINE_RE.exec(line.trim());
    if (match && match[1] && match[2]) {
      const text = (match[3] ?? '').trim();
      if (text.length > 0) {
        notes.push({
          id: `${alertId || 'alert'}-note-${notes.length + 1}`,
          createdAt: match[1],
          authorName: match[2],
          note: text,
        });
      }
      continue;
    }
    if (notes.length > 0 && line.trim().length > 0) {
      const last = notes[notes.length - 1]!;
      last.note = `${last.note}\n${line}`;
    } else if (notes.length === 0) {
      baseLines.push(line);
    }
  }

  return {
    baseDescription: baseLines.join('\n').trim(),
    notes,
  };
}

/**
 * Thuật toán: Trích Xuất Địa Chỉ IP Nguồn Từ Nhật Ký Liên Kết Hoặc Mô Tả Kỹ Thuật DLP (`extractAlertSourceIp`)
 * Mục đích: Loại bỏ tình trạng cột IP luôn hiển thị `—` bằng cách ưu tiên `alert_audit_links[].audit_logs.ip_address` và dự phòng IPv4 trong mô tả (#03).
 */
export function extractAlertSourceIp(
  links?: ReadonlyArray<{ audit_logs?: { ip_address?: string | null } | null }> | null,
  rawDescription?: string | null,
): string | null {
  if (Array.isArray(links)) {
    for (const link of links) {
      const ip = link.audit_logs?.ip_address?.trim();
      if (ip) return ip;
    }
  }
  if (rawDescription) {
    const match = IPV4_EXTRACT_RE.exec(rawDescription);
    if (match && match[1]) return match[1];
  }
  return null;
}

const VALID_ALERT_TRANSITIONS: Record<alert_status, alert_status[]> = {
  OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
  INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'OPEN'],
  RESOLVED: ['INVESTIGATING'],
  FALSE_POSITIVE: ['INVESTIGATING'],
};

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/u;

/**
 * Thuật toán: Chuẩn hóa khoảng lọc ngày `[from, to]` — mở rộng `to = YYYY-MM-DD` tới `T23:59:59.999Z` và từ chối `from > to` (`BUG-061`).
 */
export function resolveSocDateRangeBounds(
  fromRaw?: string | Date | null,
  toRaw?: string | Date | null,
): { gte?: Date; lte?: Date } | undefined {
  if (!fromRaw && !toRaw) return undefined;

  let gte: Date | undefined;
  let lte: Date | undefined;

  if (fromRaw) {
    const str = typeof fromRaw === 'string' ? fromRaw.trim() : '';
    gte =
      typeof fromRaw === 'string' && DATE_ONLY_RE.test(str)
        ? new Date(`${str}T00:00:00.000Z`)
        : new Date(fromRaw);
    if (Number.isNaN(gte.getTime())) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid "from" date filter.',
      });
    }
  }

  if (toRaw) {
    const str = typeof toRaw === 'string' ? toRaw.trim() : '';
    lte =
      typeof toRaw === 'string' && DATE_ONLY_RE.test(str)
        ? new Date(`${str}T23:59:59.999Z`)
        : new Date(toRaw);
    if (Number.isNaN(lte.getTime())) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid "to" date filter.',
      });
    }
  }

  if (gte && lte && gte.getTime() > lte.getTime()) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: '"from" date must not be later than "to" date.',
    });
  }

  return {
    ...(gte ? { gte } : {}),
    ...(lte ? { lte } : {}),
  };
}

/**
 * Thuật toán: Tổng hợp bộ lọc Prisma `SecurityAlertWhereInput` từ tập tham số truy vấn trạng thái, mức độ và khoảng thời gian.
 */
export function buildSecurityAlertsWhere(
  query: QuerySecurityAlertsInput,
): Prisma.SecurityAlertWhereInput {
  const where: Prisma.SecurityAlertWhereInput = {};
  if (query.status) where.status = query.status;
  if (query.severity) where.severity = query.severity;
  if (query.alertType) where.alert_type = query.alertType;
  if (query.detectedUserId) where.detected_user_id = query.detectedUserId;
  if (query.documentId) where.document_id = query.documentId;
  if (query.assignedTo) where.assigned_to = query.assignedTo;
  if (query.search && query.search.trim().length > 0) {
    const term = query.search.trim();
    where.OR = [
      { title: { contains: term, mode: 'insensitive' } },
      { description: { contains: term, mode: 'insensitive' } },
      { alert_type: { contains: term, mode: 'insensitive' } },
      {
        users_security_alerts_detected_user_idTousers: {
          OR: [
            { username: { contains: term, mode: 'insensitive' } },
            { full_name: { contains: term, mode: 'insensitive' } },
          ],
        },
      },
    ];
  }

  const dateBounds = resolveSocDateRangeBounds(query.from, query.to);
  if (dateBounds) {
    where.detected_at = dateBounds;
  }
  return where;
}

/**
 * Thuật toán: Kiểm chứng cạnh chuyển đổi trạng thái hợp lệ trên đồ thị `VALID_ALERT_TRANSITIONS` và bắt buộc
 * `resolutionNote` tối thiểu 5 ký tự khi chuyển sang `RESOLVED` hoặc `FALSE_POSITIVE`.
 */
export function validateAlertStatusTransition(
  currentStatus: alert_status,
  input: UpdateAlertStatusInput,
): { resolvedAt: Date | null; resolutionNote: string | null } {
  const targetStatus = input.status;
  if (!VALID_ALERT_TRANSITIONS[currentStatus]?.includes(targetStatus)) {
    throw new BadRequestException({
      errorCode: AppErrorCode.ALERT_INVALID_TRANSITION,
      message: `Cannot transition alert from ${currentStatus} to ${targetStatus}.`,
    });
  }

  const isResolving = targetStatus === 'RESOLVED' || targetStatus === 'FALSE_POSITIVE';
  if (isResolving && (!input.resolutionNote || input.resolutionNote.trim().length < 5)) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RESOLUTION_NOTE_REQUIRED,
      message:
        'Resolution note of at least 5 characters is required when resolving or marking false positive.',
    });
  }

  return {
    resolvedAt: isResolving ? new Date() : null,
    resolutionNote: isResolving ? input.resolutionNote!.trim() : null,
  };
}

interface BaseAlertRow {
  id: string;
  alert_type: string;
  severity: severity_level;
  status: alert_status;
  title: string;
  description: string;
  detected_user_id: bigint | null;
  users_security_alerts_detected_user_idTousers?: {
    id: bigint;
    username: string;
    full_name: string;
    employee_code: string | null;
  } | null;
  document_id: string | null;
  detected_at: Date;
  assigned_to: bigint | null;
  users_security_alerts_assigned_toTousers?: {
    id: bigint;
    username: string;
    full_name: string;
  } | null;
  resolved_at: Date | null;
  resolution_note: string | null;
  alert_audit_links?: Array<{
    audit_logs?: {
      ip_address?: string | null;
    } | null;
  }>;
  _count?: { alert_audit_links: number } | null;
}

/**
 * Thuật toán: Ánh xạ dòng bản ghi `security_alerts` cơ sở sang cấu trúc phản hồi `AlertDetail` chuẩn hóa kèm `notes[]` và `ipAddress`.
 */
export function mapAlertBaseDetail(a: BaseAlertRow): AlertDetail {
  const { baseDescription, notes } = parseAlertDescriptionAndNotes(a.description, a.id);
  const ipAddress = extractAlertSourceIp(a.alert_audit_links, baseDescription);
  return {
    id: a.id,
    alertType: a.alert_type,
    severity: a.severity,
    status: a.status,
    title: a.title,
    description: baseDescription,
    ipAddress,
    notes,
    detectedUserId: a.detected_user_id?.toString() ?? null,
    detectedUser: a.users_security_alerts_detected_user_idTousers
      ? {
          id: a.users_security_alerts_detected_user_idTousers.id.toString(),
          username: a.users_security_alerts_detected_user_idTousers.username,
          fullName: a.users_security_alerts_detected_user_idTousers.full_name,
          employeeCode: a.users_security_alerts_detected_user_idTousers.employee_code,
        }
      : null,
    documentId: a.document_id,
    detectedAt: a.detected_at.toISOString(),
    assignedTo: a.assigned_to?.toString() ?? null,
    assignedToUser: a.users_security_alerts_assigned_toTousers
      ? {
          id: a.users_security_alerts_assigned_toTousers.id.toString(),
          username: a.users_security_alerts_assigned_toTousers.username,
          fullName: a.users_security_alerts_assigned_toTousers.full_name,
        }
      : null,
    resolvedAt: a.resolved_at?.toISOString() ?? null,
    resolutionNote: a.resolution_note,
    linkedAuditLogsCount: a._count?.alert_audit_links ?? 0,
  };
}

/**
 * Thuật toán: Mở rộng `AlertDetail` kèm danh sách nhật ký kiểm toán liên kết (`alert_audit_links`) và biên bản sự cố (`incident_reports`).
 */
export function mapAlertFullDetail(
  alert: Omit<BaseAlertRow, 'alert_audit_links'> & {
    alert_audit_links?: Array<{
      audit_logs?: {
        id: bigint;
        action: string;
        occurred_at: Date;
        outcome: string;
        ip_address: string | null;
      } | null;
    }>;
    incident_reports?: Array<{
      id: string;
      incident_code: string;
      title: string;
      status: string;
      created_at: Date;
    }>;
  },
): AlertDetail {
  return {
    ...mapAlertBaseDetail(alert),
    linkedAuditLogs: (alert.alert_audit_links ?? []).map((l) => ({
      id: l.audit_logs?.id ? l.audit_logs.id.toString() : '',
      action: l.audit_logs?.action ?? '',
      occurredAt: l.audit_logs?.occurred_at ? l.audit_logs.occurred_at.toISOString() : '',
      outcome: l.audit_logs?.outcome ?? '',
      ipAddress: l.audit_logs?.ip_address ?? null,
    })),
    incidentReports: (alert.incident_reports ?? []).map((i) => ({
      id: i.id,
      incidentCode: i.incident_code,
      title: i.title,
      status: i.status,
      createdAt: i.created_at ? i.created_at.toISOString() : '',
    })),
  };
}
