/**
 * @module AccessRequestValidationHelper
 * Algorithm: Bell-LaPadula Clearance Dominance, SoD, Anti-Enumeration & Duplicate-Pending Guard.
 * Kiểm tra tiền điều kiện an ninh trước khi khởi tạo yêu cầu truy cập và ánh xạ DTO chuẩn hóa.
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  resolveClassificationDefaultViewDays,
  type CreateAccessRequestInput,
} from '@sda/contracts';
import {
  assertWithinDocumentRetention,
  formatRetentionDateIso,
  resolveRetentionCeilingUtc,
} from '../access-grants/grant-retention-bounds.helper.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { hasPrivilegedNonBusinessCapability } from '../documents/pep-context-builder.js';
import type { AccessRequestDetail, ExistingActiveGrantSummary } from './access-requests.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Kiểm tra tiền điều kiện khởi tạo yêu cầu xin cấp quyền (Pre-Submission Security Guard).
 * Cơ chế hoạt động:
 *   1. Kiểm tra mốc `requestedFrom` không nằm trong quá khứ (> 5 phút dung sai), kiểm tra `requestedUntil > requestedFrom`
 *      và đồng bộ trần thời lượng tối đa theo `GRANT_MAX_DURATION_DAYS` (mặc định 30 ngày).
 *   2. Kiểm tra Phân tách nhiệm vụ (SoD): chặn các vai trò quản trị/kiểm toán tách biệt (`SYSTEM_ADMIN`, `AUDITOR`, `SECURITY_OFFICER`).
 *   3. Chống dò quét định danh (Anti-Enumeration D-BR11): trả `404` nếu `discoverable === false` với người không phải chủ sở hữu.
 *   4. Áp dụng thời hạn mặc định `classification_levels.default_view_days` khi không truyền `requestedUntil` và cưỡng chế
 *      `requestedUntil <= document.retention_until` (cuối ngày UTC) để ngăn yêu cầu vượt quá hạn tài liệu.
 *   5. Kiểm tra trạng thái tài liệu `ACTIVE`, bất biến độ mật Bell-LaPadula (`userRank >= requiredRank`),
 *      cờ `allow_download` của mức phân loại và chống gửi trùng yêu cầu `PENDING`.
 */
export async function validateCreateAccessRequestPreconditions(
  database: PrismaClient,
  input: CreateAccessRequestInput,
  principal: AuthPrincipal,
  now: Date,
  maxDurationDays: number = DEFAULT_GRANT_MAX_DURATION_DAYS,
): Promise<{ requestedFrom: Date; requestedUntil: Date }> {
  const effectiveMaxDays =
    Number.isFinite(maxDurationDays) && maxDurationDays >= 1
      ? Math.floor(maxDurationDays)
      : DEFAULT_GRANT_MAX_DURATION_DAYS;
  const requestedFrom = input.requestedFrom ? new Date(input.requestedFrom) : now;
  const hasExplicitUntil = Boolean(input.requestedUntil);
  let requestedUntil = input.requestedUntil
    ? new Date(input.requestedUntil)
    : new Date(requestedFrom.getTime() + 7 * 86_400_000);

  if (Number.isNaN(requestedFrom.getTime()) || Number.isNaN(requestedUntil.getTime())) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'requestedFrom and requestedUntil must be valid ISO timestamps.',
    });
  }

  // CONFLICT-RESOLVED: Đồng bộ trần thời lượng yêu cầu truy cập với GRANT_MAX_DURATION_DAYS (mặc định 30 ngày) thay vì 365 ngày lệch pha với AccessGrantsService.
  const PAST_TOLERANCE_MS = 5 * 60_000;
  const maxRequestSpanMs = effectiveMaxDays * 86_400_000;
  if (input.requestedFrom && requestedFrom.getTime() < now.getTime() - PAST_TOLERANCE_MS) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'requestedFrom cannot be in the past.',
    });
  }
  if (hasExplicitUntil) {
    if (requestedUntil.getTime() <= now.getTime()) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
        message: 'requestedUntil must be in the future.',
      });
    }
    if (requestedUntil <= requestedFrom) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
        message: 'requestedUntil must be after requestedFrom.',
      });
    }
    if (requestedUntil.getTime() - requestedFrom.getTime() > maxRequestSpanMs) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
        message: `Requested access duration cannot exceed ${effectiveMaxDays} days.`,
      });
    }
  }

  if (
    principal.restrictedNonBusiness === true ||
    principal.roles?.some(
      (role) => role === 'SYSTEM_ADMIN' || role === 'AUDITOR' || role === 'SECURITY_OFFICER',
    ) ||
    (await hasPrivilegedNonBusinessCapability(database, principal, now))
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Separated privileged roles cannot request document access.',
    });
  }

  const document = await database.document.findUnique({
    where: { id: input.documentId },
    include: {
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true },
      },
    },
  });

  if (!document || document.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document was not found.',
    });
  }

  if (document.owner_id === principal.userId) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
      message:
        'Document owner already has ownership access and cannot request access to their own document.',
    });
  }

  if (document.discoverable === false || document.status === 'DRAFT') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document was not found.',
    });
  }

  if (document.status !== 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Cannot request access to a document that is not ACTIVE.',
    });
  }

  const currentClassification = document.classification_history[0];
  if (!hasExplicitUntil) {
    const defaultViewDays = resolveClassificationDefaultViewDays(
      currentClassification?.classification_levels?.code,
      currentClassification?.classification_levels?.default_view_days,
    );
    const boundedDefaultDays = Math.min(defaultViewDays, effectiveMaxDays);
    requestedUntil = new Date(requestedFrom.getTime() + boundedDefaultDays * 86_400_000);
    const retentionCeiling = resolveRetentionCeilingUtc(document.retention_until);
    if (
      retentionCeiling &&
      retentionCeiling.getTime() > requestedFrom.getTime() &&
      requestedUntil.getTime() > retentionCeiling.getTime()
    ) {
      requestedUntil = retentionCeiling;
    }
  }

  assertWithinDocumentRetention({
    retentionUntil: document.retention_until,
    targetUntil: requestedUntil,
    now,
    context: 'REQUEST',
  });

  if (requestedUntil.getTime() <= now.getTime() || requestedUntil <= requestedFrom) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'requestedUntil must be in the future and after requestedFrom.',
    });
  }

  const requiredRank = currentClassification?.classification_levels?.rank ?? 0;
  if (requiredRank > 0 && typeof database?.userAttributeAssignment?.findFirst === 'function') {
    const clearanceAssignment = await database.userAttributeAssignment.findFirst({
      where: {
        user_id: principal.userId,
        attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
        attribute_options: { is_active: true },
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
      include: {
        attribute_definitions: { select: { is_active: true } },
        attribute_options: true,
      },
      orderBy: { attribute_options: { numeric_rank: 'desc' } },
    });
    const userRank =
      (clearanceAssignment as { attribute_definitions?: { is_active?: boolean } } | null)
        ?.attribute_definitions?.is_active === false ||
      clearanceAssignment?.attribute_options?.is_active === false
        ? 0
        : (clearanceAssignment?.attribute_options?.numeric_rank ?? 0);
    if (userRank < requiredRank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.CLEARANCE_INSUFFICIENT,
        message: 'Insufficient security clearance to request access to this document.',
      });
    }
  }

  if (
    input.requestedAction === 'DOWNLOAD' &&
    currentClassification &&
    !currentClassification.classification_levels.allow_download
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Document classification does not allow download.',
    });
  }

  const existing = await database.accessRequest.findFirst({
    where: {
      document_id: input.documentId,
      requester_id: principal.userId,
      status: 'PENDING',
    },
  });

  if (existing) {
    throw new ConflictException({
      errorCode: AppErrorCode.ACCESS_REQUEST_DUPLICATE,
      message: 'You already have a pending access request for this document.',
    });
  }

  return { requestedFrom, requestedUntil };
}

/**
 * Algorithm / Thuật toán: Ánh xạ bản ghi cơ sở dữ liệu `access_requests` sang DTO `AccessRequestDetail`.
 */
export function mapAccessRequestDetail(
  req: {
    id: string;
    document_id: string;
    requester_id: bigint;
    reason: string;
    status: string;
    submitted_at: Date;
    requested_from: Date;
    requested_until: Date;
    documents: {
      title: string;
      document_code?: string | null;
      retention_until?: Date | string | null;
      classification_history?: Array<{
        classification_levels?: {
          code?: string | null;
          default_view_days?: number | null;
          allow_download?: boolean | null;
        } | null;
      }>;
    };
    users: { full_name?: string | null; username: string; departments?: { name: string } | null };
    access_request_permissions?: Array<{ permission: string }>;
    access_request_decisions?: { decided_at?: Date | null; decision_note?: string | null } | null;
  },
  explicitAction?: 'VIEW' | 'DOWNLOAD',
  existingActiveGrant?: ExistingActiveGrantSummary | null,
): AccessRequestDetail {
  const activeClassLevel = req.documents.classification_history?.[0]?.classification_levels;
  const documentClassificationCode = activeClassLevel?.code ?? undefined;
  const documentRetentionUntil = formatRetentionDateIso(req.documents.retention_until);
  const documentDefaultViewDays = activeClassLevel
    ? resolveClassificationDefaultViewDays(
        activeClassLevel.code,
        activeClassLevel.default_view_days,
      )
    : undefined;
  const documentAllowDownload =
    typeof activeClassLevel?.allow_download === 'boolean'
      ? activeClassLevel.allow_download
      : undefined;

  // CONFLICT-RESOLVED: Unified AccessRequestDetail DTO mapping between createRequest and listRequests, bổ sung retention/defaultViewDays/existingActiveGrant cho hộp thoại duyệt chủ sở hữu.
  const base: AccessRequestDetail = {
    id: req.id,
    documentId: req.document_id,
    documentTitle: req.documents.title,
    documentCode: req.documents.document_code,
    ...(documentClassificationCode !== undefined ? { documentClassificationCode } : {}),
    ...(documentRetentionUntil !== null ? { documentRetentionUntil } : {}),
    ...(documentDefaultViewDays !== undefined ? { documentDefaultViewDays } : {}),
    ...(documentAllowDownload !== undefined ? { documentAllowDownload } : {}),
    ...(existingActiveGrant !== undefined ? { existingActiveGrant } : {}),
    requestorId: req.requester_id.toString(),
    requestorName: req.users.full_name || req.users.username,
    requestorUsername: req.users.username,
    requestorDepartment: req.users.departments?.name || 'Chung',
    requestedAction:
      explicitAction ??
      ((req.access_request_permissions?.[0]?.permission as 'VIEW' | 'DOWNLOAD') || 'VIEW'),
    justification: req.reason,
    status: req.status,
    createdAt: req.submitted_at.toISOString(),
    requestedFrom: req.requested_from.toISOString(),
    requestedUntil: req.requested_until.toISOString(),
  };

  if ('access_request_decisions' in req) {
    base.decidedAt = req.access_request_decisions?.decided_at?.toISOString() ?? null;
    base.decisionNote = req.access_request_decisions?.decision_note ?? null;
  }

  return base;
}
