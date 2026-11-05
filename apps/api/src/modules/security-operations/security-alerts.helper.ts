import { BadRequestException } from '@nestjs/common';
import type { Prisma, alert_status, severity_level } from '@sda/database';
import {
  AppErrorCode,
  type QuerySecurityAlertsInput,
  type UpdateAlertStatusInput,
} from '@sda/contracts';

export interface AlertDetail {
  id: string;
  alertType: string;
  severity: severity_level;
  status: alert_status;
  title: string;
  description: string;
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

const VALID_ALERT_TRANSITIONS: Record<alert_status, alert_status[]> = {
  OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
  INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'OPEN'],
  RESOLVED: ['INVESTIGATING'],
  FALSE_POSITIVE: ['INVESTIGATING'],
};

/**
 * Algorithm: Multi-Predicate Security Alert Filter Construction.
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

  if (query.from || query.to) {
    where.detected_at = {
      ...(query.from ? { gte: new Date(query.from) } : {}),
      ...(query.to ? { lte: new Date(query.to) } : {}),
    };
  }
  return where;
}

/**
 * Algorithm: Finite-State Alert Transition & Mandatory Resolution Note Validation.
 * Enforces allowed directed edges on `alert_status` and requires ≥5-char `resolutionNote`
 * whenever transitioning into `RESOLVED` or `FALSE_POSITIVE`.
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
  _count?: { alert_audit_links: number } | null;
}

export function mapAlertBaseDetail(a: BaseAlertRow): AlertDetail {
  return {
    id: a.id,
    alertType: a.alert_type,
    severity: a.severity,
    status: a.status,
    title: a.title,
    description: a.description,
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

export function mapAlertFullDetail(
  alert: BaseAlertRow & {
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
