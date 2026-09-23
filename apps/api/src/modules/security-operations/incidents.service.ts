import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  Logger,
  Optional,
} from '@nestjs/common';
import { randomUUID, randomBytes } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import type { incident_status } from '@sda/database';
import {
  AppErrorCode,
  type CreateIncidentReportInput,
  type UpdateIncidentReportInput,
  type SubmitIncidentReportInput,
  type CloseIncidentReportInput,
  type CreateIncidentActionInput,
  type CompleteIncidentActionInput,
  type QueryIncidentReportsInput,
} from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

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

  /**
   * Asserts that the actor is authorized to mutate incidents.
   * Auditor has read-only access and cannot mutate incidents (D-BR19 & SoD).
   */
  private assertCanMutate(actor: AuthPrincipal): void {
    const roles = actor.roles ?? [];
    if (roles.includes('AUDITOR') && !roles.includes('SECURITY_OFFICER')) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS,
        message: 'Auditors are strictly read-only and cannot create, modify or close incidents.',
      });
    }
  }

  /**
   * Generates a human-readable unique incident code, e.g., INC-2026-A1B2C3
   */
  private generateIncidentCode(): string {
    const year = new Date().getFullYear();
    const suffix = randomBytes(3).toString('hex').toUpperCase();
    return `INC-${year}-${suffix}`;
  }

  /**
   * Creates a new incident report in DRAFT status.
   */
  async createIncidentReport(
    input: CreateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    this.assertCanMutate(actor);

    // Verify alert exists if provided
    if (input.alertId) {
      const alert = await this.database.securityAlert.findUnique({
        where: { id: input.alertId },
      });
      if (!alert) {
        throw new NotFoundException({
          errorCode: AppErrorCode.ALERT_NOT_FOUND,
          message: `Linked security alert ${input.alertId} was not found.`,
        });
      }
    }

    const id = randomUUID();
    const incidentCode = this.generateIncidentCode();

    const created = await this.database.incidentReport.create({
      data: {
        id,
        incident_code: incidentCode,
        alert_id: input.alertId ?? null,
        title: input.title.trim(),
        summary: input.summary.trim(),
        findings: input.findings?.trim() ?? null,
        impact_assessment: input.impactAssessment?.trim() ?? null,
        status: 'DRAFT',
        prepared_by: actor.userId,
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_REPORT_CREATED',
        objectType: 'INCIDENT_REPORT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentCode,
          alertId: input.alertId ?? null,
          title: input.title,
        },
      });
    }

    return this.getIncidentReportById(created.id);
  }

  /**
   * Lists incident reports with filters and pagination.
   */
  async listIncidentReports(query: QueryIncidentReportsInput): Promise<{
    data: IncidentReportDetail[];
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
    const where: import('@sda/database').Prisma.IncidentReportWhereInput = {};

    if (query.status) where.status = query.status;
    if (query.preparedBy) where.prepared_by = query.preparedBy;
    if (query.alertId) where.alert_id = query.alertId;

    if (query.from || query.to) {
      where.created_at = {};
      if (query.from) {
        where.created_at.gte = new Date(query.from);
      }
      if (query.to) {
        where.created_at.lte = new Date(query.to);
      }
    }

    const take = query.pageSize + 1;
    const skip = (query.page - 1) * query.pageSize;
    const orderBy = { [query.sort]: query.order };

    const reports = await this.database.incidentReport.findMany({
      where,
      orderBy,
      take,
      skip,
      include: {
        users_incident_reports_prepared_byTousers: {
          select: { id: true, username: true, full_name: true },
        },
        incident_actions: {
          include: {
            users: {
              select: { id: true, username: true, full_name: true },
            },
          },
        },
      },
    });

    const hasMore = reports.length > query.pageSize;
    const items = hasMore ? reports.slice(0, query.pageSize) : reports;

    return {
      data: items.map((r) => this.mapToDetail(r)),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

  /**
   * Retrieves single incident report by ID with actions.
   */
  async getIncidentReportById(id: string): Promise<IncidentReportDetail> {
    const report = await this.database.incidentReport.findUnique({
      where: { id },
      include: {
        users_incident_reports_prepared_byTousers: {
          select: { id: true, username: true, full_name: true },
        },
        incident_actions: {
          include: {
            users: {
              select: { id: true, username: true, full_name: true },
            },
          },
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

    return this.mapToDetail(report);
  }

  /**
   * Updates an incident report (allowed in DRAFT or IN_REVIEW).
   */
  async updateIncidentReport(
    id: string,
    input: UpdateIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    this.assertCanMutate(actor);

    const report = await this.database.incidentReport.findUnique({
      where: { id },
    });

    if (!report) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
        message: `Incident report ${id} was not found.`,
      });
    }

    if (report.status === 'CLOSED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
        message: 'Cannot modify a closed incident report.',
      });
    }

    const updateData: import('@sda/database').Prisma.IncidentReportUpdateInput = {};
    if (input.title !== undefined) updateData.title = input.title.trim();
    if (input.summary !== undefined) updateData.summary = input.summary.trim();
    if (input.findings !== undefined) updateData.findings = input.findings.trim();
    if (input.impactAssessment !== undefined) {
      updateData.impact_assessment = input.impactAssessment.trim();
    }

    const updated = await this.database.incidentReport.update({
      where: { id },
      data: updateData,
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_REPORT_UPDATED',
        objectType: 'INCIDENT_REPORT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentCode: report.incident_code,
          fieldsUpdated: Object.keys(input),
        },
      });
    }

    return this.getIncidentReportById(updated.id);
  }

  /**
   * Submits an incident report to Owner or Administrator.
   */
  async submitIncidentReport(
    id: string,
    input: SubmitIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    this.assertCanMutate(actor);

    const report = await this.database.incidentReport.findUnique({
      where: { id },
    });

    if (!report) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
        message: `Incident report ${id} was not found.`,
      });
    }

    if (report.status !== 'DRAFT') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
        message: `Cannot submit incident report currently in ${report.status} status.`,
      });
    }

    const updated = await this.database.incidentReport.update({
      where: { id },
      data: {
        status: 'SUBMITTED',
        submitted_at: new Date(),
        submitted_to_owner: input.submittedToOwner ?? null,
        submitted_to_admin: input.submittedToAdmin ?? null,
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_REPORT_SUBMITTED',
        objectType: 'INCIDENT_REPORT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentCode: report.incident_code,
          submittedToOwner: input.submittedToOwner?.toString() ?? null,
          submittedToAdmin: input.submittedToAdmin?.toString() ?? null,
        },
      });
    }

    return this.getIncidentReportById(updated.id);
  }

  /**
   * Closes an incident report.
   */
  async closeIncidentReport(
    id: string,
    input: CloseIncidentReportInput,
    actor: AuthPrincipal,
  ): Promise<IncidentReportDetail> {
    this.assertCanMutate(actor);

    const report = await this.database.incidentReport.findUnique({
      where: { id },
    });

    if (!report) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
        message: `Incident report ${id} was not found.`,
      });
    }

    if (report.status === 'CLOSED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
        message: 'Incident report is already closed.',
      });
    }

    const updated = await this.database.incidentReport.update({
      where: { id },
      data: {
        status: 'CLOSED',
        closed_at: new Date(),
        summary: input.closingNote
          ? `${report.summary}\n[CLOSED NOTE]: ${input.closingNote.trim()}`
          : report.summary,
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_REPORT_CLOSED',
        objectType: 'INCIDENT_REPORT',
        objectId: id,
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentCode: report.incident_code,
          closingNote: input.closingNote ?? null,
        },
      });
    }

    return this.getIncidentReportById(updated.id);
  }

  /**
   * Adds a recommended action to an incident report.
   */
  async addIncidentAction(
    incidentReportId: string,
    input: CreateIncidentActionInput,
    actor: AuthPrincipal,
  ): Promise<IncidentActionDetail> {
    this.assertCanMutate(actor);

    const report = await this.database.incidentReport.findUnique({
      where: { id: incidentReportId },
    });

    if (!report) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
        message: `Incident report ${incidentReportId} was not found.`,
      });
    }

    if (report.status === 'CLOSED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
        message: 'Cannot add actions to a closed incident report.',
      });
    }

    const action = await this.database.incidentAction.create({
      data: {
        incident_report_id: incidentReportId,
        action_type: input.actionType.trim(),
        recommendation: input.recommendation.trim(),
        assigned_to: input.assignedTo ?? null,
        due_at: input.dueAt ? new Date(input.dueAt) : null,
      },
      include: {
        users: {
          select: { id: true, username: true, full_name: true },
        },
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_ACTION_CREATED',
        objectType: 'INCIDENT_ACTION',
        objectId: action.id.toString(),
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentReportId,
          actionType: input.actionType,
          assignedTo: input.assignedTo?.toString() ?? null,
          dueAt: input.dueAt ?? null,
        },
      });
    }

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

  /**
   * Completes an incident action (mandatory completion note).
   */
  async completeIncidentAction(
    actionId: bigint,
    input: CompleteIncidentActionInput,
    actor: AuthPrincipal,
  ): Promise<IncidentActionDetail> {
    this.assertCanMutate(actor);

    const action = await this.database.incidentAction.findUnique({
      where: { id: actionId },
    });

    if (!action) {
      throw new NotFoundException({
        errorCode: AppErrorCode.INCIDENT_ACTION_NOT_FOUND,
        message: `Incident action ${actionId} was not found.`,
      });
    }

    if (!input.completionNote || input.completionNote.trim().length < 5) {
      throw new BadRequestException({
        errorCode: AppErrorCode.COMPLETION_NOTE_REQUIRED,
        message: 'Completion note of at least 5 characters is required.',
      });
    }

    const updated = await this.database.incidentAction.update({
      where: { id: actionId },
      data: {
        completed_at: new Date(),
        completion_note: input.completionNote.trim(),
      },
      include: {
        users: {
          select: { id: true, username: true, full_name: true },
        },
      },
    });

    if (this.auditWriter) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'INCIDENT_ACTION_COMPLETED',
        objectType: 'INCIDENT_ACTION',
        objectId: actionId.toString(),
        outcome: 'SUCCESS',
        chainPartition: 'SECURITY_OPERATIONS',
        details: {
          incidentReportId: action.incident_report_id,
          completionNote: input.completionNote.trim(),
        },
      });
    }

    return {
      id: updated.id.toString(),
      actionType: updated.action_type,
      recommendation: updated.recommendation,
      assignedTo: updated.assigned_to?.toString() ?? null,
      assignedToUser: updated.users
        ? {
            id: updated.users.id.toString(),
            username: updated.users.username,
            fullName: updated.users.full_name,
          }
        : null,
      dueAt: updated.due_at?.toISOString() ?? null,
      completedAt: updated.completed_at?.toISOString() ?? null,
      completionNote: updated.completion_note,
      createdAt: updated.created_at.toISOString(),
    };
  }

  private mapToDetail(report: {
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
    incident_actions?: Array<{
      id: bigint;
      action_type: string;
      recommendation: string;
      assigned_to: bigint | null;
      users?: { id: bigint; username: string; full_name: string } | null;
      due_at: Date | null;
      completed_at: Date | null;
      completion_note: string | null;
      created_at: Date;
    }>;
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
      actions: (report.incident_actions ?? []).map((a) => ({
        id: a.id.toString(),
        actionType: a.action_type,
        recommendation: a.recommendation,
        assignedTo: a.assigned_to?.toString() ?? null,
        assignedToUser: a.users
          ? {
              id: a.users.id.toString(),
              username: a.users.username,
              fullName: a.users.full_name,
            }
          : null,
        dueAt: a.due_at?.toISOString() ?? null,
        completedAt: a.completed_at?.toISOString() ?? null,
        completionNote: a.completion_note,
        createdAt: a.created_at.toISOString(),
      })),
    };
  }
}
