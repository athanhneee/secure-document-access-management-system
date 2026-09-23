import { Injectable, NotFoundException, BadRequestException, Optional } from '@nestjs/common';
import { getDatabaseClient, Prisma } from '@sda/database';
import type { alert_status, severity_level } from '@sda/database';
import {
  AppErrorCode,
  type QuerySecurityAlertsInput,
  type UpdateAlertStatusInput,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

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

@Injectable()
export class SecurityAlertsService {
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Lists security alerts with pagination, sorting, and filters.
   */
  async listAlerts(query: QuerySecurityAlertsInput): Promise<{
    data: AlertDetail[];
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
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

    const take = query.pageSize + 1;
    const skip = (query.page - 1) * query.pageSize;
    const orderBy =
      query.sort === 'severity' ? { severity: query.order } : { detected_at: query.order };

    const alerts = await this.database.securityAlert.findMany({
      where,
      orderBy,
      take,
      skip,
      include: {
        users_security_alerts_detected_user_idTousers: {
          select: { id: true, username: true, full_name: true, employee_code: true },
        },
        users_security_alerts_assigned_toTousers: {
          select: { id: true, username: true, full_name: true },
        },
        _count: {
          select: { alert_audit_links: true },
        },
      },
    });

    const hasMore = alerts.length > query.pageSize;
    const items = hasMore ? alerts.slice(0, query.pageSize) : alerts;

    return {
      data: items.map((a) => ({
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
        linkedAuditLogsCount: a._count.alert_audit_links,
      })),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

  /**
   * Retrieves single security alert by ID including linked audit logs and incidents.
   */
  async getAlertById(id: string): Promise<AlertDetail> {
    const alert = await this.database.securityAlert.findUnique({
      where: { id },
      include: {
        users_security_alerts_detected_user_idTousers: {
          select: { id: true, username: true, full_name: true, employee_code: true },
        },
        users_security_alerts_assigned_toTousers: {
          select: { id: true, username: true, full_name: true },
        },
        alert_audit_links: {
          take: 50,
          include: {
            audit_logs: {
              select: {
                id: true,
                action: true,
                occurred_at: true,
                outcome: true,
                ip_address: true,
              },
            },
          },
        },
        incident_reports: {
          select: {
            id: true,
            incident_code: true,
            title: true,
            status: true,
            created_at: true,
          },
        },
        _count: {
          select: { alert_audit_links: true },
        },
      },
    });

    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }

    return {
      id: alert.id,
      alertType: alert.alert_type,
      severity: alert.severity,
      status: alert.status,
      title: alert.title,
      description: alert.description,
      detectedUserId: alert.detected_user_id?.toString() ?? null,
      detectedUser: alert.users_security_alerts_detected_user_idTousers
        ? {
            id: alert.users_security_alerts_detected_user_idTousers.id.toString(),
            username: alert.users_security_alerts_detected_user_idTousers.username,
            fullName: alert.users_security_alerts_detected_user_idTousers.full_name,
            employeeCode: alert.users_security_alerts_detected_user_idTousers.employee_code,
          }
        : null,
      documentId: alert.document_id,
      detectedAt: alert.detected_at.toISOString(),
      assignedTo: alert.assigned_to?.toString() ?? null,
      assignedToUser: alert.users_security_alerts_assigned_toTousers
        ? {
            id: alert.users_security_alerts_assigned_toTousers.id.toString(),
            username: alert.users_security_alerts_assigned_toTousers.username,
            fullName: alert.users_security_alerts_assigned_toTousers.full_name,
          }
        : null,
      resolvedAt: alert.resolved_at?.toISOString() ?? null,
      resolutionNote: alert.resolution_note,
      linkedAuditLogsCount: alert._count?.alert_audit_links ?? 0,
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

  /**
   * Updates alert status with strict state machine validation and mandatory resolution notes.
   */
  async updateAlertStatus(
    id: string,
    input: UpdateAlertStatusInput,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    const alert = await this.database.securityAlert.findUnique({
      where: { id },
    });

    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }

    const currentStatus = alert.status;
    const targetStatus = input.status;

    // Validate state machine transitions
    const validTransitions: Record<alert_status, alert_status[]> = {
      OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
      INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'OPEN'],
      RESOLVED: ['INVESTIGATING'],
      FALSE_POSITIVE: ['INVESTIGATING'],
    };

    if (!validTransitions[currentStatus]?.includes(targetStatus)) {
      throw new BadRequestException({
        errorCode: AppErrorCode.ALERT_INVALID_TRANSITION,
        message: `Cannot transition alert from ${currentStatus} to ${targetStatus}.`,
      });
    }

    // RESOLVED or FALSE_POSITIVE strictly requires resolution note
    const isResolving = targetStatus === 'RESOLVED' || targetStatus === 'FALSE_POSITIVE';
    if (isResolving && (!input.resolutionNote || input.resolutionNote.trim().length < 5)) {
      throw new BadRequestException({
        errorCode: AppErrorCode.RESOLUTION_NOTE_REQUIRED,
        message:
          'Resolution note of at least 5 characters is required when resolving or marking false positive.',
      });
    }

    const resolvedAt = isResolving ? new Date() : null;
    const resolutionNote = isResolving ? input.resolutionNote!.trim() : null;

    const updated = await this.database.securityAlert.update({
      where: { id },
      data: {
        status: targetStatus,
        resolved_at: resolvedAt,
        resolution_note: resolutionNote,
      },
    });

    // Record audit log
    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'SECURITY_ALERT_STATUS_UPDATED',
        objectType: 'SECURITY_ALERT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          previousStatus: currentStatus,
          newStatus: targetStatus,
          resolutionNote,
        },
      });
    }

    return this.getAlertById(updated.id);
  }

  /**
   * Assigns an alert to a Security Officer.
   */
  async assignAlert(
    id: string,
    assignedToUserId: bigint | null,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    const alert = await this.database.securityAlert.findUnique({
      where: { id },
    });

    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }

    if (assignedToUserId) {
      const user = await this.database.user.findUnique({
        where: { id: assignedToUserId },
      });
      if (!user) {
        throw new NotFoundException(`Assigned user ${assignedToUserId} was not found.`);
      }
    }

    const updated = await this.database.securityAlert.update({
      where: { id },
      data: {
        assigned_to: assignedToUserId,
        status: alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'SECURITY_ALERT_ASSIGNED',
        objectType: 'SECURITY_ALERT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          assignedToUserId: assignedToUserId?.toString() ?? null,
          previousAssignee: alert.assigned_to?.toString() ?? null,
        },
      });
    }

    return this.getAlertById(updated.id);
  }

  /**
   * Adds an investigation note to a security alert.
   */
  async addAlertNote(id: string, note: string, actor: AuthPrincipal): Promise<AlertDetail> {
    const alert = await this.database.securityAlert.findUnique({
      where: { id },
    });

    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }

    const timestamp = new Date().toISOString();
    const entry = `\n[${timestamp}] ${actor.username}: ${note.trim()}`;
    const newDescription = (alert.description ?? '') + entry;

    await this.database.securityAlert.update({
      where: { id },
      data: {
        description: newDescription,
        status: alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'SECURITY_ALERT_NOTE_ADDED',
        objectType: 'SECURITY_ALERT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          noteLength: note.length,
        },
      });
    }

    return this.getAlertById(id);
  }
}
