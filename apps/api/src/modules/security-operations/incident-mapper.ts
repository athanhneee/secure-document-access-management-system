/**
 * Module: IncidentMapper — Ràng buộc phân tách nhiệm vụ (SoD), sinh mã sự cố mật mã CSPRNG và ánh xạ DTO báo cáo sự cố.
 */
import { ForbiddenException } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type { Prisma, incident_status } from '@sda/database';
import { AppErrorCode, type QueryIncidentReportsInput } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';

export interface IncidentActionDetail {
  id: string;
  actionType: string;
  recommendation: string;
  assignedTo: string | null;
  assignedToUser?: {
    id: string;
    username: string;
    fullName: string;
  } | null;
  dueAt: string | null;
  completedAt: string | null;
  completionNote: string | null;
  createdAt: string;
}

export interface IncidentReportDetail {
  id: string;
  incidentCode: string;
  alertId: string | null;
  title: string;
  summary: string;
  findings: string | null;
  impactAssessment: string | null;
  status: incident_status;
  preparedBy: string;
  preparedByUser?: {
    id: string;
    username: string;
    fullName: string;
  } | null;
  submittedToOwner: string | null;
  submittedToAdmin: string | null;
  createdAt: string;
  submittedAt: string | null;
  closedAt: string | null;
  actions: IncidentActionDetail[];
}

/**
 * Thuật toán: Chốt chặn phân tách nhiệm vụ chống kiểm toán viên sửa đổi sự cố (Separation-of-Duties Auditor Read-Only Guard)
 * Mục đích: Thực thi quy tắc D-BR19 đảm bảo vai trò kiểm toán độc lập chỉ được phép đọc, không thể tạo/sửa/đóng sự cố.
 * Cơ chế hoạt động:
 *   - Từ chối ngay với `ForbiddenException` (`AUDITOR_CANNOT_MUTATE_INCIDENTS`) nếu người gọi giữ vai trò `AUDITOR` mà không đồng thời giữ vai trò `SECURITY_OFFICER`.
 *
 * Algorithm: Separation-of-Duties (SoD) Auditor Read-Only Guard (D-BR19).
 * Rejects incident mutations when principal holds `AUDITOR` without `SECURITY_OFFICER`.
 */
export function assertActorCanMutateIncidents(actor: AuthPrincipal): void {
  const roles = actor.roles ?? [];
  if (roles.includes('AUDITOR') && !roles.includes('SECURITY_OFFICER')) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS,
      message: 'Auditors are strictly read-only and cannot create, modify or close incidents.',
    });
  }
}

/**
 * Thuật toán: Sinh mã tham chiếu sự cố theo năm từ nguồn ngẫu nhiên mật mã CSPRNG (`INC-YYYY-XXXXXX`)
 * Mục đích: Tạo mã định danh sự cố dễ tra cứu với 24-bit entropy ngẫu nhiên (`randomBytes(3)`).
 * Cơ chế hoạt động:
 *   - Ghép năm hiện tại với chuỗi hex 6 ký tự in hoa sinh từ `crypto.randomBytes(3)`.
 *
 * Algorithm: Human-Readable CSPRNG Incident Code Generation (`INC-<YYYY>-<6HEX>`).
 */
export function generateIncidentCode(): string {
  const year = new Date().getFullYear();
  const suffix = randomBytes(3).toString('hex').toUpperCase();
  return `INC-${year}-${suffix}`;
}

export function buildIncidentQueryWhere(
  query: QueryIncidentReportsInput,
): Prisma.IncidentReportWhereInput {
  const where: Prisma.IncidentReportWhereInput = {};
  if (query.status) where.status = query.status;
  if (query.preparedBy) where.prepared_by = query.preparedBy;
  if (query.alertId) where.alert_id = query.alertId;

  if (query.from || query.to) {
    where.created_at = {};
    if (query.from) where.created_at.gte = new Date(query.from);
    if (query.to) where.created_at.lte = new Date(query.to);
  }
  return where;
}

export function mapIncidentActionToDetail(action: {
  id: bigint;
  action_type: string;
  recommendation: string;
  assigned_to: bigint | null;
  users?: { id: bigint; username: string; full_name: string } | null;
  due_at: Date | null;
  completed_at: Date | null;
  completion_note: string | null;
  created_at: Date;
}): IncidentActionDetail {
  return {
    id: action.id.toString(),
    actionType: action.action_type,
    recommendation: action.recommendation,
    assignedTo: action.assigned_to?.toString() ?? null,
    assignedToUser: action.users
      ? {
          id: action.users.id.toString(),
          username: action.users.username,
          fullName: action.users.full_name,
        }
      : null,
    dueAt: action.due_at?.toISOString() ?? null,
    completedAt: action.completed_at?.toISOString() ?? null,
    completionNote: action.completion_note,
    createdAt: action.created_at.toISOString(),
  };
}

export function mapIncidentReportToDetail(report: {
  id: string;
  incident_code: string;
  alert_id: string | null;
  title: string;
  summary: string;
  findings: string | null;
  impact_assessment: string | null;
  status: incident_status;
  prepared_by: bigint;
  users_incident_reports_prepared_byTousers?: {
    id: bigint;
    username: string;
    full_name: string;
  } | null;
  submitted_to_owner: bigint | null;
  submitted_to_admin: bigint | null;
  created_at: Date;
  submitted_at: Date | null;
  closed_at: Date | null;
  incident_actions?: Array<Parameters<typeof mapIncidentActionToDetail>[0]>;
}): IncidentReportDetail {
  return {
    id: report.id,
    incidentCode: report.incident_code,
    alertId: report.alert_id,
    title: report.title,
    summary: report.summary,
    findings: report.findings ?? '',
    impactAssessment: report.impact_assessment,
    status: report.status,
    preparedBy: report.prepared_by.toString(),
    preparedByUser: report.users_incident_reports_prepared_byTousers
      ? {
          id: report.users_incident_reports_prepared_byTousers.id.toString(),
          username: report.users_incident_reports_prepared_byTousers.username,
          fullName: report.users_incident_reports_prepared_byTousers.full_name,
        }
      : null,
    submittedToOwner: report.submitted_to_owner?.toString() ?? null,
    submittedToAdmin: report.submitted_to_admin?.toString() ?? null,
    createdAt: report.created_at.toISOString(),
    submittedAt: report.submitted_at?.toISOString() ?? null,
    closedAt: report.closed_at?.toISOString() ?? null,
    actions: (report.incident_actions ?? []).map(mapIncidentActionToDetail),
  };
}
