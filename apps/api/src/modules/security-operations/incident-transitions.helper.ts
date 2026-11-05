/**
 * Module: Incident Lifecycle Transitions Helper
 * Algorithm: Enforces Separation of Duties (`assertActorCanMutateIncidents`) and finite-state machine guards
 *   (`DRAFT -> SUBMITTED -> CLOSED`, immutable once `CLOSED`) with tamper-evident `SECURITY_OPERATIONS` audit logs.
 */
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient, Prisma } from '@sda/database';
import {
  AppErrorCode,
  type CloseIncidentReportInput,
  type CreateIncidentReportInput,
  type SubmitIncidentReportInput,
  type UpdateIncidentReportInput,
} from '@sda/contracts';
import type { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { assertActorCanMutateIncidents, generateIncidentCode } from './incident-mapper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

async function requireIncidentRow(database: PrismaClient, id: string) {
  const report = await database.incidentReport.findUnique({ where: { id } });
  if (!report) {
    throw new NotFoundException({
      errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
      message: `Incident report ${id} was not found.`,
    });
  }
  return report;
}

async function writeIncidentAudit(
  auditWriter: AuditWriterService | undefined,
  actor: AuthPrincipal,
  action: string,
  objectId: string,
  details: Record<string, unknown>,
): Promise<void> {
  if (!auditWriter) return;
  await auditWriter.writeLog({
    actorUserId: actor.userId,
    actorUsername: actor.username,
    action,
    objectType: 'INCIDENT_REPORT',
    objectId,
    outcome: 'SUCCESS',
    chainPartition: 'SECURITY_OPERATIONS',
    details,
  });
}

/**
 * Algorithm: Draft Incident Initialization with Linked-Alert Referential Check
 */
export async function executeCreateIncidentReport(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  input: CreateIncidentReportInput,
  actor: AuthPrincipal,
): Promise<string> {
  assertActorCanMutateIncidents(actor);

  if (input.alertId) {
    const alert = await database.securityAlert.findUnique({ where: { id: input.alertId } });
    if (!alert) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ALERT_NOT_FOUND,
        message: `Linked security alert ${input.alertId} was not found.`,
      });
    }
  }

  const id = randomUUID();
  const incidentCode = generateIncidentCode();
  const created = await database.incidentReport.create({
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

  await writeIncidentAudit(auditWriter, actor, 'INCIDENT_REPORT_CREATED', id, {
    incidentCode,
    alertId: input.alertId ?? null,
    title: input.title,
  });
  return created.id;
}

/**
 * Algorithm: Closed-State Guarded Partial Incident Update
 */
export async function executeUpdateIncidentReport(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  id: string,
  input: UpdateIncidentReportInput,
  actor: AuthPrincipal,
): Promise<string> {
  assertActorCanMutateIncidents(actor);
  const report = await requireIncidentRow(database, id);
  if (report.status === 'CLOSED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
      message: 'Cannot modify a closed incident report.',
    });
  }

  const updateData: Prisma.IncidentReportUpdateInput = {};
  if (input.title !== undefined) updateData.title = input.title.trim();
  if (input.summary !== undefined) updateData.summary = input.summary.trim();
  if (input.findings !== undefined) updateData.findings = input.findings.trim();
  if (input.impactAssessment !== undefined) {
    updateData.impact_assessment = input.impactAssessment.trim();
  }

  const updated = await database.incidentReport.update({ where: { id }, data: updateData });
  await writeIncidentAudit(auditWriter, actor, 'INCIDENT_REPORT_UPDATED', id, {
    incidentCode: report.incident_code,
    fieldsUpdated: Object.keys(input),
  });
  return updated.id;
}

/**
 * Algorithm: Incident State Transition (`DRAFT -> SUBMITTED`)
 */
export async function executeSubmitIncidentReport(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  id: string,
  input: SubmitIncidentReportInput,
  actor: AuthPrincipal,
): Promise<string> {
  assertActorCanMutateIncidents(actor);
  const report = await requireIncidentRow(database, id);
  if (report.status !== 'DRAFT') {
    throw new BadRequestException({
      errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
      message: `Cannot submit incident report currently in ${report.status} status.`,
    });
  }

  const updated = await database.incidentReport.update({
    where: { id },
    data: {
      status: 'SUBMITTED',
      submitted_at: new Date(),
      submitted_to_owner: input.submittedToOwner ?? null,
      submitted_to_admin: input.submittedToAdmin ?? null,
    },
  });
  await writeIncidentAudit(auditWriter, actor, 'INCIDENT_REPORT_SUBMITTED', id, {
    incidentCode: report.incident_code,
    submittedToOwner: input.submittedToOwner?.toString() ?? null,
    submittedToAdmin: input.submittedToAdmin?.toString() ?? null,
  });
  return updated.id;
}

/**
 * Algorithm: Terminal Incident Closure (`* -> CLOSED`)
 */
export async function executeCloseIncidentReport(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  id: string,
  input: CloseIncidentReportInput,
  actor: AuthPrincipal,
): Promise<string> {
  assertActorCanMutateIncidents(actor);
  const report = await requireIncidentRow(database, id);
  // CONFLICT-RESOLVED: Chỉ cho phép đóng báo cáo sự cố đã ở trạng thái SUBMITTED (DRAFT -> SUBMITTED -> CLOSED) (HIGH-12)
  if (report.status !== 'SUBMITTED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
      message:
        report.status === 'CLOSED'
          ? 'Incident report is already closed.'
          : `Cannot close incident report currently in ${report.status} status; submit it first.`,
    });
  }

  const updated = await database.incidentReport.update({
    where: { id },
    data: {
      status: 'CLOSED',
      closed_at: new Date(),
      summary: input.closingNote
        ? `${report.summary}\n[CLOSED NOTE]: ${input.closingNote.trim()}`
        : report.summary,
    },
  });
  await writeIncidentAudit(auditWriter, actor, 'INCIDENT_REPORT_CLOSED', id, {
    incidentCode: report.incident_code,
    closingNote: input.closingNote ?? null,
  });
  return updated.id;
}
