/**
 * Module: IncidentActionsHelper — Xử lý vòng đời hành động khắc phục sự cố (Remediation Action Attachment & Parent-Bound Completion).
 */
import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CompleteIncidentActionInput,
  type CreateIncidentActionInput,
} from '@sda/contracts';
import type { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import {
  assertActorCanMutateIncidents,
  mapIncidentActionToDetail,
  type IncidentActionDetail,
} from './incident-mapper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Gắn khuyến nghị hành động khắc phục vào hồ sơ sự cố đang mở (Open-Incident Remediation Action Attachment)
 * Mục đích: Phân công hạng mục khắc phục (`actionType`, `recommendation`, người thực hiện, hạn `dueAt`) cho sự cố chưa đóng.
 * Cơ chế hoạt động:
 *   - Kiểm tra phân tách nhiệm vụ SoD (`assertActorCanMutateIncidents`), xác minh hồ sơ cha tồn tại và chưa ở trạng thái `CLOSED`.
 *   - Khởi tạo bản ghi `IncidentAction` và phát nhật ký kiểm toán `INCIDENT_ACTION_CREATED`.
 *
 * Algorithm: Open-Incident Remediation Action Attachment.
 * Enforces SoD mutation guard, verifies target incident exists and is not `CLOSED`,
 * creates the remediation action row, and emits `INCIDENT_ACTION_CREATED` audit trail.
 */
export async function executeAddIncidentAction(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  incidentReportId: string,
  input: CreateIncidentActionInput,
  actor: AuthPrincipal,
): Promise<IncidentActionDetail> {
  assertActorCanMutateIncidents(actor);

  const report = await database.incidentReport.findUnique({
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

  const action = await database.incidentAction.create({
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

  if (auditWriter) {
    await auditWriter.writeLog({
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

  return mapIncidentActionToDetail(action);
}

/**
 * Thuật toán: Nghiệm thu hoàn tất hành động khắc phục có ràng buộc cha-con & ghi chú bắt buộc (Parent-Bound Idempotent Action Completion)
 * Mục đích: Đánh dấu hoàn thành hạng mục khắc phục đúng một lần kèm ghi chú nghiệm thu tối thiểu 5 ký tự.
 * Cơ chế hoạt động:
 *   - Kiểm tra SoD và đối chiếu `action.incident_report_id === expectedIncidentId` để chống tham chiếu chéo đối tượng (IDOR giữa các sự cố).
 *   - Chặn hoàn tất lại nếu `completed_at != null` hoặc khi báo cáo sự cố cha đã `CLOSED`; bắt buộc `completionNote.trim().length >= 5` trước khi cập nhật và ghi audit `INCIDENT_ACTION_COMPLETED`.
 *
 * Algorithm: Parent-Bound Idempotent Incident Action Completion.
 * Verifies parent incident ownership (`expectedIncidentId`), rejects re-completion or completion on
 * `CLOSED` incidents, enforces ≥5-char completion note, and records `INCIDENT_ACTION_COMPLETED`.
 */
export async function executeCompleteIncidentAction(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  actionId: bigint,
  input: CompleteIncidentActionInput,
  actor: AuthPrincipal,
  expectedIncidentId?: string,
): Promise<IncidentActionDetail> {
  assertActorCanMutateIncidents(actor);

  const action = await database.incidentAction.findUnique({
    where: { id: actionId },
  });

  if (
    !action ||
    (expectedIncidentId !== undefined && action.incident_report_id !== expectedIncidentId)
  ) {
    throw new NotFoundException({
      errorCode: AppErrorCode.INCIDENT_ACTION_NOT_FOUND,
      message: `Incident action ${actionId} was not found.`,
    });
  }

  if (action.completed_at !== null && action.completed_at !== undefined) {
    throw new BadRequestException({
      errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
      message: 'Incident action has already been completed.',
    });
  }

  if (typeof database?.incidentReport?.findUnique === 'function') {
    const parentReport = await database.incidentReport.findUnique({
      where: { id: action.incident_report_id },
    });
    if (parentReport && parentReport.status === 'CLOSED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INCIDENT_INVALID_TRANSITION,
        message: 'Cannot complete actions on a closed incident report.',
      });
    }
  }

  if (!input.completionNote || input.completionNote.trim().length < 5) {
    throw new BadRequestException({
      errorCode: AppErrorCode.COMPLETION_NOTE_REQUIRED,
      message: 'Completion note of at least 5 characters is required.',
    });
  }

  const updated = await database.incidentAction.update({
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

  if (auditWriter) {
    await auditWriter.writeLog({
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

  return mapIncidentActionToDetail(updated);
}
