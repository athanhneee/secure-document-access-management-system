/**
 * @module GrantValidationHelper
 * Algorithm: Multi-Stage Pre-Grant Security Gate (Time Bounds, RBAC Ownership, Bell-LaPadula & ABAC PDP).
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateAccessGrantInput } from '@sda/contracts';
import type { AppConfigService } from '../../config/config.service.js';
import type { AbacService } from '../abac/abac.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import {
  assertActorClearanceDominatesDocument,
  isPureTechnicalOrAuditRole,
} from '../documents/document-access-guard.helper.js';
import {
  buildGrantResourceAttributes,
  buildGrantSubjectAttributes,
  buildRoleGrantSubjectAttributes,
  fetchUserClearanceRank,
} from './grant-pip.helper.js';
import { validateGrantTargetAndSod } from './grant-target-sod.helper.js';
import {
  assertWithinDocumentRetention,
  assertWithinMaxGrantDuration,
  formatRetentionDateIso,
} from './grant-retention-bounds.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ValidateCreateGrantParams {
  input: CreateAccessGrantInput;
  principal: AuthPrincipal;
  context: RequestContext;
  now: Date;
  maxDurationDays: number;
  database: PrismaClient;
  authorization: AuthorizationService;
  abac: AbacService;
  config: AppConfigService;
}

/**
 * Algorithm / Thuật toán: Kiểm chứng toàn diện tiền điều kiện cấp quyền truy cập có thời hạn (Steps 1-6).
 *   1. Kiểm tra biên khoảng thời gian (`validUntil > validFrom`) và trần `maxDurationDays`.
 *   2. Xác minh tài liệu tồn tại, không `ARCHIVED` và đang `ACTIVE`; xác minh chủ sở hữu hoặc quyền `ACCESS_GRANT/CREATE`.
 *   3. Xác minh chủ thể đích (`USER`/`ROLE`), quy tắc Phân tách nhiệm vụ (SoD), và `accessRequestId`.
 *   4. Kiểm tra bất biến độ mật Bell-LaPadula (`userRank >= documentRank`), cờ `allow_download` và chính sách ABAC cho mọi quyền.
 */
export async function validateCreateGrantPreconditions(params: ValidateCreateGrantParams): Promise<{
  validFrom: Date;
  validUntil: Date;
  maxMs: number;
  retentionUntilIso?: string | null | undefined;
  documentTitle?: string | undefined;
  documentCode?: string | undefined;
}> {
  const { input, principal, now, maxDurationDays, database, abac } = params;
  const validFrom = input.validFrom ? new Date(input.validFrom) : now;
  const validUntil = new Date(input.validUntil);

  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Separated privileged roles cannot grant document access.',
    });
  }

  if (
    Number.isNaN(validFrom.getTime()) ||
    Number.isNaN(validUntil.getTime()) ||
    validUntil <= validFrom
  ) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'validUntil must be after validFrom.',
    });
  }

  if (validUntil <= now) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'validUntil must be in the future.',
    });
  }

  const { maxDurationMs: maxMs } = assertWithinMaxGrantDuration({
    validFrom,
    validUntil,
    now,
    maxDurationDays,
    mode: 'CREATE',
  });

  const document = await database.document.findUnique({
    where: { id: input.documentId },
    include: {
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true, business_categories: true },
      },
    },
  });

  if (!document || document.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document was not found.',
    });
  }

  // CONFLICT-RESOLVED: Chỉ chủ sở hữu tài liệu mới được cấp quyền truy cập, triệt tiêu lỗ hổng BOLA tự cấp quyền vượt cổng PEP.
  if (document.owner_id !== principal.userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.FORBIDDEN,
      message: 'Only the document owner can grant access to this document.',
    });
  }

  if (input.principalType === 'USER' && input.principalUserId === document.owner_id) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
      message:
        'Document owner already has ownership access and cannot create a direct access grant to themselves.',
    });
  }

  const currentClassification = document.classification_history[0];
  const documentRank = currentClassification?.classification_levels?.rank ?? 0;
  await assertActorClearanceDominatesDocument(database, principal.userId, documentRank, now);

  if (document.status === 'ARCHIVED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot grant access to an archived document.',
    });
  }
  if (document.status !== 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Document must be in ACTIVE status to grant access.',
    });
  }

  // CONFLICT-RESOLVED: Cưỡng chế thời điểm kết thúc giấy phép không được vượt quá ngày hạn lưu trữ bảo mật (retention_until) của tài liệu.
  assertWithinDocumentRetention({
    retentionUntil: document.retention_until,
    targetUntil: validUntil,
    now,
    context: 'GRANT',
  });

  await validateGrantTargetAndSod(database, input, now);

  if (input.principalType === 'USER' && input.principalUserId) {
    const userRank = (await fetchUserClearanceRank(database, input.principalUserId, now)) ?? 0;
    if (userRank < documentRank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_CLEARANCE_INSUFFICIENT,
        message: 'User clearance level is insufficient for this document classification.',
      });
    }
  }

  if (
    input.permissions.includes('DOWNLOAD') &&
    currentClassification &&
    !currentClassification.classification_levels.allow_download
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Document classification does not allow download.',
    });
  }

  // CONFLICT-RESOLVED: Chấm điểm ABAC và kiểm tra độ mật Bell-LaPadula theo tập người nhận của vai trò đích thay vì mượn độ mật của người cấp khi `principalType === 'ROLE'` (HIGH-11).
  let subjectAttributes: {
    clearanceRank: number | null;
    departmentId: string | null;
    employmentStatus: string | null;
    projects: string[];
  };
  if (input.principalType === 'USER' && input.principalUserId) {
    subjectAttributes = await buildGrantSubjectAttributes(database, input.principalUserId, now);
  } else if (input.principalType === 'ROLE' && input.principalRoleId) {
    const roleSubject = await buildRoleGrantSubjectAttributes(database, input.principalRoleId, now);
    if ((roleSubject.clearanceRank ?? 0) < documentRank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_CLEARANCE_INSUFFICIENT,
        message:
          'Target role holders do not all satisfy the clearance level required for this document classification.',
      });
    }
    subjectAttributes = roleSubject;
  } else {
    subjectAttributes = {
      clearanceRank: 0,
      departmentId: null,
      employmentStatus: null,
      projects: [],
    };
  }
  const resourceAttributes = buildGrantResourceAttributes(document, currentClassification);
  const staticIssuanceEnvironment = {
    currentTime: validFrom.toISOString(),
    ip: '127.0.0.1',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 0,
  };

  for (const permission of input.permissions) {
    const abacResult = await abac.evaluate({
      resourceType: 'DOCUMENT',
      action: permission as 'VIEW' | 'DOWNLOAD',
      subject: subjectAttributes,
      resource: resourceAttributes,
      environment: staticIssuanceEnvironment,
    });
    if (abacResult.decision === 'DENY') {
      const missingAttributes: string[] = [];
      if (abacResult.reasonCode === 'MISSING_REQUIRED_ATTRIBUTE') {
        if (subjectAttributes.departmentId === null) missingAttributes.push('SUBJECT_DEPARTMENT');
        if (subjectAttributes.clearanceRank === null) missingAttributes.push('CLEARANCE_LEVEL');
        if (subjectAttributes.employmentStatus === null)
          missingAttributes.push('EMPLOYMENT_STATUS');
        if (resourceAttributes.classificationRank === null)
          missingAttributes.push('CLASSIFICATION_RANK');
        if (resourceAttributes.category === null) missingAttributes.push('RESOURCE_CATEGORY');
      }
      const missingSuffix =
        missingAttributes.length > 0 ? ` (${missingAttributes.join(', ')})` : '';
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_ABAC_DENIED,
        message: `ABAC policy denied ${permission} access: ${abacResult.reasonCode}${missingSuffix}.`,
        details: {
          reasonCode: abacResult.reasonCode,
          ...(missingAttributes.length > 0 ? { missingAttributes } : {}),
        },
      });
    }
  }

  return {
    validFrom,
    validUntil,
    maxMs,
    retentionUntilIso: formatRetentionDateIso(document.retention_until),
    documentTitle: document.title,
    documentCode: document.document_code,
  };
}
