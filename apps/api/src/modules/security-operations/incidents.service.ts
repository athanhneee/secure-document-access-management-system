/**
 * @module IncidentsService
 * Thuật toán: Quản lý vòng đời ứng cứu sự cố an ninh SOC — cưỡng chế Phân tách Nhiệm vụ (SoD) đối với kiểm toán viên,
 * kiểm soát phạm vi phòng ban, chuyển trạng thái hữu hạn (`DRAFT -> SUBMITTED -> CLOSED`), phân trang nhìn trước `pageSize + 1`
 * và ghi nhật ký chuỗi băm trên phân vùng `SECURITY_OPERATIONS`.
 */
import { Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CloseIncidentReportInput,
  type CompleteIncidentActionInput,
  type CreateIncidentActionInput,
  type CreateIncidentReportInput,
  type QueryIncidentReportsInput,
  type SubmitIncidentReportInput,
  type UpdateIncidentReportInput,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import {
  executeAddIncidentAction,
  executeCompleteIncidentAction,
} from './incident-actions.helper.js';
import {
  buildIncidentQueryWhere,
  mapIncidentReportToDetail,
  type IncidentActionDetail,
  type IncidentReportDetail,
} from './incident-mapper.js';
import {
  executeCloseIncidentReport,
  executeCreateIncidentReport,
  executeReviewIncidentReport,
  executeSubmitIncidentReport,
  executeUpdateIncidentReport,
} from './incident-transitions.helper.js';
import {
  applyIncidentScopeToWhere,
  assertAlertInDepartmentScope,
  assertIncidentInDepartmentScope,
  resolveIncidentDepartmentScope,
} from './security-operations-scope.helper.js';

export type { IncidentActionDetail, IncidentReportDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);
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
    this.logger.log('IncidentsService initialized');
  }

  private emitIncidentUpdated(id: string, action: string, status?: string): void {
    this.realtime?.publish({
      type: 'INCIDENT_REPORT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      payload: { id, action, ...(status ? { status } : {}) },
    });
  }

  /**
   * Thuật toán: Khởi tạo biên bản sự cố an ninh ở trạng thái `DRAFT` có kiểm tra phạm vi phòng ban của cảnh báo gốc.
   */
  async createIncidentReport(
    input: CreateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    if (input.alertId) {
      await assertAlertInDepartmentScope(
        this.database,
        this.authorization,
        actor,
        input.alertId,
        'MANAGE',
      );
    }
    const id = await executeCreateIncidentReport(this.database, this.auditWriter, input, actor);
    const detail = await this.getIncidentReportById(id, actor);
    this.emitIncidentUpdated(detail.id, 'CREATED', detail.status);
    return detail;
  }

  /**
   * Thuật toán: Liệt kê danh sách biên bản sự cố phân trang nhìn trước `pageSize + 1` kèm tổng số bản ghi thực (`total`) theo phạm vi phòng ban.
   */
  async listIncidentReports(
    query: QueryIncidentReportsInput,
    actor?: AuthPrincipal,
  ): Promise<{
    data: IncidentReportDetail[];
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
    const allowedDepts = await resolveIncidentDepartmentScope(this.authorization, actor, 'VIEW');
    const where = applyIncidentScopeToWhere(buildIncidentQueryWhere(query), allowedDepts);
    const [reports, totalCount] = await Promise.all([
      this.database.incidentReport.findMany({
        where,
        orderBy: { [query.sort]: query.order },
        take: query.pageSize + 1,
        skip: (query.page - 1) * query.pageSize,
        include: {
          users_incident_reports_prepared_byTousers: {
            select: { id: true, username: true, full_name: true },
          },
          incident_actions: {
            include: { users: { select: { id: true, username: true, full_name: true } } },
          },
        },
      }),
      typeof this.database.incidentReport.count === 'function'
        ? this.database.incidentReport.count({ where })
        : Promise.resolve<number | null>(null),
    ]);

    const hasMore = reports.length > query.pageSize;
    const items = hasMore ? reports.slice(0, query.pageSize) : reports;
    const total =
      totalCount ?? (query.page - 1) * query.pageSize + items.length + (hasMore ? 1 : 0);
    const totalPages = Math.max(1, Math.ceil(total / query.pageSize));
    return {
      data: items.map(mapIncidentReportToDetail),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
      total,
      meta: { page: query.page, pageSize: query.pageSize, total, totalPages, hasMore },
    };
  }

  /**
   * Thuật toán: Truy xuất chi tiết biên bản sự cố kèm danh sách hành động khắc phục sắp xếp tăng dần theo thời gian.
   */
  async getIncidentReportById(id: string, actor?: AuthPrincipal): Promise<IncidentReportDetail> {
    await assertIncidentInDepartmentScope(this.database, this.authorization, actor, id, 'VIEW');
    const report = await this.database.incidentReport.findUnique({
      where: { id },
      include: {
        users_incident_reports_prepared_byTousers: {
          select: { id: true, username: true, full_name: true },
        },
        incident_actions: {
          include: { users: { select: { id: true, username: true, full_name: true } } },
          orderBy: { created_at: 'asc' },
        },
      },
    });

    if (!report) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
        message: `Incident report ${id} was not found.`,
      });
    }

    return mapIncidentReportToDetail(report);
  }

  /**
   * Thuật toán: Cập nhật nội dung phân tích nguyên nhân gốc rễ và mức độ ảnh hưởng của biên bản sự cố trong phạm vi quản lý.
   */
  async updateIncidentReport(
    id: string,
    input: UpdateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    await assertIncidentInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const updatedId = await executeUpdateIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    const detail = await this.getIncidentReportById(updatedId, actor);
    this.emitIncidentUpdated(detail.id, 'UPDATED', detail.status);
    return detail;
  }

  /**
   * Thuật toán: Đệ trình biên bản sự cố (`DRAFT -> SUBMITTED`) sau khi hoàn tất phân tích sơ bộ.
   */
  async submitIncidentReport(
    id: string,
    input: SubmitIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    await assertIncidentInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const updatedId = await executeSubmitIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    const detail = await this.getIncidentReportById(updatedId, actor);
    this.emitIncidentUpdated(detail.id, 'SUBMITTED', detail.status);
    return detail;
  }

  /**
   * Thuật toán: Chuyển biên bản sự cố đã đệ trình sang trạng thái đang thẩm định (`SUBMITTED -> IN_REVIEW`) (#18).
   */
  async reviewIncidentReport(id: string, actor: AuthPrincipal): Promise<IncidentReportDetail> {
    await assertIncidentInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const updatedId = await executeReviewIncidentReport(this.database, this.auditWriter, id, actor);
    const detail = await this.getIncidentReportById(updatedId, actor);
    this.emitIncidentUpdated(detail.id, 'IN_REVIEW', detail.status);
    return detail;
  }

  /**
   * Thuật toán: Đóng biên bản sự cố (`SUBMITTED | IN_REVIEW -> CLOSED`) có xác minh điều kiện hoàn tất các hành động khắc phục (N13).
   */
  async closeIncidentReport(
    id: string,
    input: CloseIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    await assertIncidentInDepartmentScope(this.database, this.authorization, actor, id, 'MANAGE');
    const updatedId = await executeCloseIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    const detail = await this.getIncidentReportById(updatedId, actor);
    this.emitIncidentUpdated(detail.id, 'CLOSED', detail.status);
    return detail;
  }

  /**
   * Thuật toán: Bổ sung đầu việc hành động khắc phục (`IncidentAction`) gắn với biên bản sự cố.
   */
  async addIncidentAction(
    incidentReportId: string,
    input: CreateIncidentActionInput,
    actor: AuthPrincipal,
  ): Promise<IncidentActionDetail> {
    await assertIncidentInDepartmentScope(
      this.database,
      this.authorization,
      actor,
      incidentReportId,
      'MANAGE',
    );
    const created = await executeAddIncidentAction(
      this.database,
      this.auditWriter,
      incidentReportId,
      input,
      actor,
    );
    this.emitIncidentUpdated(incidentReportId, 'ACTION_ADDED');
    return created;
  }

  /**
   * Thuật toán: Đánh dấu hoàn thành hành động khắc phục có đối chiếu chéo `expectedIncidentId` chống tham chiếu chéo IDOR.
   */
  async completeIncidentAction(
    actionId: bigint,
    input: CompleteIncidentActionInput,
    actor: AuthPrincipal,
    expectedIncidentId?: string,
  ): Promise<IncidentActionDetail> {
    if (expectedIncidentId) {
      await assertIncidentInDepartmentScope(
        this.database,
        this.authorization,
        actor,
        expectedIncidentId,
        'MANAGE',
      );
    }
    const completed = await executeCompleteIncidentAction(
      this.database,
      this.auditWriter,
      actionId,
      input,
      actor,
      expectedIncidentId,
    );
    if (expectedIncidentId) {
      this.emitIncidentUpdated(expectedIncidentId, 'ACTION_COMPLETED');
    }
    return completed;
  }
}
