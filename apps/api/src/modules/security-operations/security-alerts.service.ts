import { Injectable, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type QuerySecurityAlertsInput,
  type UpdateAlertStatusInput,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import {
  buildSecurityAlertsWhere,
  mapAlertBaseDetail,
  mapAlertFullDetail,
  validateAlertStatusTransition,
  type AlertDetail,
} from './security-alerts.helper.js';

export type { AlertDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

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
   * Algorithm: Lookahead Paginated Security Alert Query (`pageSize + 1` slice).
   */
  async listAlerts(query: QuerySecurityAlertsInput): Promise<{
    data: AlertDetail[];
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
    const where = buildSecurityAlertsWhere(query);
    const orderBy =
      query.sort === 'severity' ? { severity: query.order } : { detected_at: query.order };

    const alerts = await this.database.securityAlert.findMany({
      where,
      orderBy,
      take: query.pageSize + 1,
      skip: (query.page - 1) * query.pageSize,
      include: {
        users_security_alerts_detected_user_idTousers: {
          select: { id: true, username: true, full_name: true, employee_code: true },
        },
        users_security_alerts_assigned_toTousers: {
          select: { id: true, username: true, full_name: true },
        },
        _count: { select: { alert_audit_links: true } },
      },
    });

    const hasMore = alerts.length > query.pageSize;
    const items = hasMore ? alerts.slice(0, query.pageSize) : alerts;

    return {
      data: items.map(mapAlertBaseDetail),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

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
        _count: { select: { alert_audit_links: true } },
      },
    });

    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }

    return mapAlertFullDetail(alert);
  }

  /**
   * Algorithm: State-Machine Validated Security Alert Status Mutation.
   */
  async updateAlertStatus(
    id: string,
    input: UpdateAlertStatusInput,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    const alert = await this.requireAlert(id);
    const { resolvedAt, resolutionNote } = validateAlertStatusTransition(alert.status, input);

    const updated = await this.database.securityAlert.update({
      where: { id },
      data: {
        status: input.status,
        resolved_at: resolvedAt,
        resolution_note: resolutionNote,
      },
    });

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
          previousStatus: alert.status,
          newStatus: input.status,
          resolutionNote,
        },
      });
    }

    return this.getAlertById(updated.id);
  }

  /**
   * Algorithm: Auto-Triage Security Alert Assignment (`OPEN` -> `INVESTIGATING`).
   */
  async assignAlert(
    id: string,
    assignedToUserId: bigint | null,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    const alert = await this.requireAlert(id);

    if (assignedToUserId) {
      const user = await this.database.user.findUnique({ where: { id: assignedToUserId } });
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
   * Algorithm: Append-Only Timestamped Investigation Note Accrual.
   */
  async addAlertNote(id: string, note: string, actor: AuthPrincipal): Promise<AlertDetail> {
    const alert = await this.requireAlert(id);
    const entry = `\n[${new Date().toISOString()}] ${actor.username}: ${note.trim()}`;

    await this.database.securityAlert.update({
      where: { id },
      data: {
        description: (alert.description ?? '') + entry,
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
        details: { noteLength: note.length },
      });
    }

    return this.getAlertById(id);
  }

  private async requireAlert(id: string) {
    const alert = await this.database.securityAlert.findUnique({ where: { id } });
    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Security alert ${id} was not found.`,
      });
    }
    return alert;
  }
}
