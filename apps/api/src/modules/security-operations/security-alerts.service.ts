/**
 * @module SecurityAlertsService
 * Thuật toán: Quản lý cảnh báo an ninh SOC — truy vấn phân trang nhìn trước `pageSize + 1` theo phạm vi phòng ban,
 * kiểm chứng chuyển đổi máy trạng thái hữu hạn (`OPEN <-> INVESTIGATING -> RESOLVED | FALSE_POSITIVE`),
 * tự động chuyển sang `INVESTIGATING` khi phân công cán bộ xử lý hoặc ghi chú điều tra và ghi nhật ký chuỗi băm.
 */
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type QuerySecurityAlertsInput,
  type UpdateAlertStatusInput,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import {
  buildSecurityAlertsWhere,
  mapAlertBaseDetail,
  mapAlertFullDetail,
  validateAlertStatusTransition,
  type AlertDetail,
} from './security-alerts.helper.js';
import {
  applyAlertScopeToWhere,
  assertAlertInDepartmentScope,
  resolveAlertDepartmentScope,
} from './security-operations-scope.helper.js';

export type { AlertDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class SecurityAlertsService {
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
    @Optional() private readonly authorization?: AuthorizationService,
    @Optional() private readonly realtime?: RealtimeEventsService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Truy vấn danh sách cảnh báo an ninh phân trang nhìn trước (`pageSize + 1`) có giới hạn phạm vi phòng ban.
   */
  async listAlerts(
    query: QuerySecurityAlertsInput,
    actor?: AuthPrincipal,
  ): Promise<{
    data: AlertDetail[];
    page: number;
    pageSize: number;
    hasMore: boolean;
    total: number;
    meta: {
      page: number;
      pageSize: number;
      total: number;
      totalPages: number;
      hasMore: boolean;
    };
  }> {
    const allowedDepts = await resolveAlertDepartmentScope(this.authorization, actor, 'VIEW');
    const where = applyAlertScopeToWhere(buildSecurityAlertsWhere(query), allowedDepts);
    const orderBy =
      query.sort === 'severity' ? { severity: query.order } : { detected_at: query.order };

    const [alerts, totalCount] = await Promise.all([
      this.database.securityAlert.findMany({
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
          alert_audit_links: {
            take: 3,
            select: { audit_logs: { select: { ip_address: true } } },
          },
          _count: { select: { alert_audit_links: true } },
        },
      }),
      typeof this.database.securityAlert.count === 'function'
        ? this.database.securityAlert.count({ where })
        : Promise.resolve<number | null>(null),
    ]);

    const hasMore = alerts.length > query.pageSize;
    const items = hasMore ? alerts.slice(0, query.pageSize) : alerts;
    const total =
      totalCount ?? (query.page - 1) * query.pageSize + items.length + (hasMore ? 1 : 0);
    const totalPages = Math.max(1, Math.ceil(total / query.pageSize));

    return {
      data: items.map(mapAlertBaseDetail),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
      total,
      meta: {
        page: query.page,
        pageSize: query.pageSize,
        total,
        totalPages,
        hasMore,
      },
    };
  }

  /**
   * Thuật toán: Nạp chi tiết cảnh báo an ninh kèm tối đa 50 nhật ký kiểm toán liên kết và danh sách biên bản sự cố.
   */
  async getAlertById(id: string, actor?: AuthPrincipal): Promise<AlertDetail> {
    await assertAlertInDepartmentScope(this.database, this.authorization, actor, id, 'VIEW');
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

  private async resolveAlertTargetDepartmentId(alert: {
    detected_user_id?: bigint | null;
    document_id?: string | null;
  }): Promise<string | null> {
    try {
      if (alert.detected_user_id && typeof this.database?.user?.findUnique === 'function') {
        const u = await this.database.user.findUnique({
          where: { id: alert.detected_user_id },
          select: { department_id: true },
        });
        if (u?.department_id != null) return u.department_id.toString();
      }
      if (alert.document_id && typeof this.database?.document?.findUnique === 'function') {
        const d = await this.database.document.findUnique({
          where: { id: alert.document_id },
          select: { department_id: true },
        });
        if (d?.department_id != null) return d.department_id.toString();
      }
    } catch {
      // Ignore department lookup failure on partial unit test mocks
    }
    return null;
  }

  /**
   * Thuật toán: Cập nhật nguyên tử trạng thái cảnh báo theo đồ thị chuyển trạng thái hợp lệ, bắt buộc ghi chú kết luận khi đóng cảnh báo
   * và gộp luôn `investigationNote` (nếu có) bằng SQL `CASE` nguyên tử chống ghi đè đồng thời (#09, `BUG-061`).
   */
  async updateAlertStatus(
    id: string,
    input: UpdateAlertStatusInput,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    await assertAlertInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const alert = await this.requireAlert(id);
    const { resolvedAt, resolutionNote } = validateAlertStatusTransition(alert.status, input);
    const trimmedInvNote = input.investigationNote?.trim();
    const noteLine =
      trimmedInvNote && trimmedInvNote.length > 0
        ? `[${new Date().toISOString()}] ${actor.username}: ${trimmedInvNote}`
        : undefined;

    // MED-08: Dùng Compare-And-Swap trên trạng thái nguồn (`status = alert.status`) để ngăn 2 SOC đồng thời bỏ qua kiểm định chuyển trạng thái.
    if (noteLine !== undefined && typeof this.database.$executeRawUnsafe === 'function') {
      const affected = await this.database.$executeRawUnsafe(
        `UPDATE public.security_alerts
         SET status = $2::public.alert_status,
             resolved_at = $3,
             resolution_note = $4,
             description = CASE
               WHEN description IS NULL OR description = '' THEN $5
               ELSE description || E'\\n' || $5
             END
         WHERE id = $1::uuid AND status = $6::public.alert_status`,
        id,
        input.status,
        resolvedAt,
        resolutionNote,
        noteLine,
        alert.status,
      );
      if (typeof affected === 'number' && affected === 0) {
        throw new ConflictException({
          errorCode: AppErrorCode.RESOURCE_CONFLICT,
          message: 'Security alert status was modified concurrently; please reload and retry.',
        });
      }
    } else {
      const nextDescription =
        noteLine !== undefined ? `${alert.description ?? ''}\n${noteLine}` : undefined;
      if (typeof this.database.securityAlert.updateMany === 'function') {
        const updated = await this.database.securityAlert.updateMany({
          where: { id, status: alert.status },
          data: {
            status: input.status,
            resolved_at: resolvedAt,
            resolution_note: resolutionNote,
            ...(nextDescription !== undefined ? { description: nextDescription } : {}),
          },
        });
        if (updated.count === 0) {
          throw new ConflictException({
            errorCode: AppErrorCode.RESOURCE_CONFLICT,
            message: 'Security alert status was modified concurrently; please reload and retry.',
          });
        }
      } else {
        await this.database.securityAlert.update({
          where: { id },
          data: {
            status: input.status,
            resolved_at: resolvedAt,
            resolution_note: resolutionNote,
            ...(nextDescription !== undefined ? { description: nextDescription } : {}),
          },
        });
      }
    }

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
          ...(trimmedInvNote ? { investigationNoteAdded: true } : {}),
        },
      });
    }

    const [detail, targetDepartmentId] = await Promise.all([
      this.getAlertById(id, actor),
      this.resolveAlertTargetDepartmentId(alert),
    ]);
    this.realtime?.publish({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId,
      payload: { id: detail.id, status: detail.status, action: 'STATUS_UPDATED' },
    });
    return detail;
  }

  /**
   * Thuật toán: Phân công cán bộ SOC `ACTIVE` phụ trách cảnh báo chưa đóng và tự động nâng trạng thái từ `OPEN` sang `INVESTIGATING` (`BUG-061`).
   */
  async assignAlert(
    id: string,
    assignedToUserId: bigint | null,
    actor: AuthPrincipal,
  ): Promise<AlertDetail> {
    await assertAlertInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const alert = await this.requireAlert(id);

    if (alert.status === 'RESOLVED' || alert.status === 'FALSE_POSITIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.ALERT_INVALID_TRANSITION,
        message: `Cannot assign a closed security alert in ${alert.status} status.`,
      });
    }

    if (assignedToUserId !== null) {
      const user = await this.database.user.findUnique({ where: { id: assignedToUserId } });
      if (!user) {
        throw new NotFoundException({
          errorCode: AppErrorCode.RESOURCE_NOT_FOUND,
          message: `Assigned user ${assignedToUserId.toString()} was not found.`,
        });
      }
      if ('status' in user && user.status !== 'ACTIVE') {
        throw new BadRequestException({
          errorCode: AppErrorCode.USER_NOT_ACTIVE,
          message: `Assigned user ${assignedToUserId.toString()} is not active.`,
        });
      }
    }

    if (typeof this.database.securityAlert.updateMany === 'function') {
      const casUpdated = await this.database.securityAlert.updateMany({
        where: { id, status: alert.status },
        data: {
          assigned_to: assignedToUserId,
          status: alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
        },
      });
      if (casUpdated.count === 0) {
        throw new ConflictException({
          errorCode: AppErrorCode.RESOURCE_CONFLICT,
          message: 'Security alert status changed concurrently before assignment.',
        });
      }
    } else {
      await this.database.securityAlert.update({
        where: { id },
        data: {
          assigned_to: assignedToUserId,
          status: alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
        },
      });
    }

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

    const [detail, targetDepartmentId] = await Promise.all([
      this.getAlertById(id, actor),
      this.resolveAlertTargetDepartmentId(alert),
    ]);
    this.realtime?.publish({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId,
      payload: { id: detail.id, status: detail.status, action: 'ASSIGNED' },
    });
    return detail;
  }

  /**
   * Thuật toán: Ghi nối tiếp nguyên tử dòng nhật ký điều tra có gắn dấu thời gian ISO-8601 vào mô tả cảnh báo bằng SQL `CASE` chống mất ghi chú đồng thời (`BUG-061`).
   */
  async addAlertNote(id: string, note: string, actor: AuthPrincipal): Promise<AlertDetail> {
    await assertAlertInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const alert = await this.requireAlert(id);
    const noteLine = `[${new Date().toISOString()}] ${actor.username}: ${note.trim()}`;

    if (typeof this.database.$executeRawUnsafe === 'function') {
      await this.database.$executeRawUnsafe(
        `UPDATE public.security_alerts
         SET description = CASE
               WHEN description IS NULL OR description = '' THEN $2
               ELSE description || E'\\n' || $2
             END,
             status = CASE
               WHEN status = 'OPEN'::public.alert_status THEN 'INVESTIGATING'::public.alert_status
               ELSE status
             END
         WHERE id = $1::uuid`,
        id,
        noteLine,
      );
    } else {
      await this.database.securityAlert.update({
        where: { id },
        data: {
          description: `${alert.description ?? ''}\n${noteLine}`,
          status: alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
        },
      });
    }

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

    const [detail, targetDepartmentId] = await Promise.all([
      this.getAlertById(id, actor),
      this.resolveAlertTargetDepartmentId(alert),
    ]);
    this.realtime?.publish({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId,
      payload: { id: detail.id, status: detail.status, action: 'NOTE_ADDED' },
    });
    return detail;
  }

  /**
   * Thuật toán: Tải bản ghi cảnh báo bắt buộc tồn tại trước khi cập nhật trạng thái hoặc phân công.
   */
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
