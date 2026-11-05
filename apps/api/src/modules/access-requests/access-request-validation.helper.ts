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
import { AppErrorCode, type CreateAccessRequestInput } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AccessRequestDetail } from './access-requests.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Kiểm tra tiền điều kiện khởi tạo yêu cầu xin cấp quyền (Pre-Submission Security Guard).
 * Cơ chế hoạt động:
 *   1. Chuẩn hóa khoảng thời gian yêu cầu (mặc định 7 ngày) và kiểm tra `requestedUntil > requestedFrom`.
 *   2. Kiểm tra Phân tách nhiệm vụ (SoD): chặn các vai trò quản trị/kiểm toán tách biệt (`SYSTEM_ADMIN`, `AUDITOR`, `SECURITY_OFFICER`).
 *   3. Chống dò quét định danh (Anti-Enumeration D-BR11): trả `404` nếu `discoverable === false` với người không phải chủ sở hữu.
 *   4. Kiểm tra trạng thái tài liệu `ACTIVE`, bất biến độ mật Bell-LaPadula (`userRank >= requiredRank`),
 *      cờ `allow_download` của mức phân loại và chống gửi trùng yêu cầu `PENDING`.
 */
export async function validateCreateAccessRequestPreconditions(
  database: PrismaClient,
  input: CreateAccessRequestInput,
  principal: AuthPrincipal,
  now: Date,
): Promise<{ requestedFrom: Date; requestedUntil: Date }> {
  const requestedFrom = input.requestedFrom ? new Date(input.requestedFrom) : now;
  const requestedUntil = input.requestedUntil
    ? new Date(input.requestedUntil)
    : new Date(now.getTime() + 7 * 86400000);

  if (requestedUntil <= requestedFrom) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'requestedUntil must be after requestedFrom.',
    });
  }

  if (
    principal.roles?.some(
      (role) => role === 'SYSTEM_ADMIN' || role === 'AUDITOR' || role === 'SECURITY_OFFICER',
    )
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

  if (!document || (document.discoverable === false && document.owner_id !== principal.userId)) {
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
    documents: { title: string; document_code?: string | null };
    users: { full_name?: string | null; username: string; departments?: { name: string } | null };
    access_request_permissions?: Array<{ permission: string }>;
    access_request_decisions?: { decided_at?: Date | null; decision_note?: string | null } | null;
  },
  explicitAction?: 'VIEW' | 'DOWNLOAD',
): AccessRequestDetail {
  // CONFLICT-RESOLVED: Unified AccessRequestDetail DTO mapping between createRequest and listRequests
  const base: AccessRequestDetail = {
    id: req.id,
    documentId: req.document_id,
    documentTitle: req.documents.title,
    documentCode: req.documents.document_code,
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
