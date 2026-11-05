/**
 * Module: SOC Incident Response Lifecycle & Remediation Action Service
 * Algorithm: Enforces auditor SoD exclusions, finite-state workflow transitions (`DRAFT -> SUBMITTED -> CLOSED`),
 *   lookahead `N+1` pagination, and chained `SECURITY_OPERATIONS` audit trails.
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
  executeSubmitIncidentReport,
  executeUpdateIncidentReport,
} from './incident-transitions.helper.js';

export type { IncidentActionDetail, IncidentReportDetail };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);
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
    this.logger.log('IncidentsService initialized');
  }

  async createIncidentReport(
    input: CreateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    const id = await executeCreateIncidentReport(this.database, this.auditWriter, input, actor);
    return this.getIncidentReportById(id);
  }

  /**
   * Algorithm: Lookahead N+1 Paginated Incident Report Listing
   */
  async listIncidentReports(query: QueryIncidentReportsInput): Promise<{
    data: IncidentReportDetail[];
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
    const where = buildIncidentQueryWhere(query);
    const reports = await this.database.incidentReport.findMany({
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
    });

    const hasMore = reports.length > query.pageSize;
    const items = hasMore ? reports.slice(0, query.pageSize) : reports;
    return {
      data: items.map(mapIncidentReportToDetail),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

  /**
   * Algorithm: Incident Report & Chronological Remediation Action Hydration
   */
  async getIncidentReportById(id: string): Promise<IncidentReportDetail> {
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

  async updateIncidentReport(
    id: string,
    input: UpdateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    const updatedId = await executeUpdateIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    return this.getIncidentReportById(updatedId);
  }

  async submitIncidentReport(
    id: string,
    input: SubmitIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    const updatedId = await executeSubmitIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    return this.getIncidentReportById(updatedId);
  }

  async closeIncidentReport(
    id: string,
    input: CloseIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    const updatedId = await executeCloseIncidentReport(
      this.database,
      this.auditWriter,
      id,
      input,
      actor,
    );
    return this.getIncidentReportById(updatedId);
  }

  addIncidentAction(
    incidentReportId: string,
    input: CreateIncidentActionInput,
    actor: AuthPrincipal,
  ): Promise<IncidentActionDetail> {
    return executeAddIncidentAction(
      this.database,
      this.auditWriter,
      incidentReportId,
      input,
      actor,
    );
  }

  completeIncidentAction(
    actionId: bigint,
    input: CompleteIncidentActionInput,
    actor: AuthPrincipal,
    expectedIncidentId?: string,
  ): Promise<IncidentActionDetail> {
    return executeCompleteIncidentAction(
      this.database,
      this.auditWriter,
      actionId,
      input,
      actor,
      expectedIncidentId,
    );
  }
}
