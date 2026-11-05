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
  buildGrantResourceAttributes,
  buildGrantSubjectAttributes,
  fetchUserClearanceRank,
  isTrustedClientNetwork,
} from './grant-pip.helper.js';
import { validateGrantTargetAndSod } from './grant-target-sod.helper.js';

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
export async function validateCreateGrantPreconditions(
  params: ValidateCreateGrantParams,
): Promise<{ validFrom: Date; validUntil: Date; maxMs: number }> {
  const { input, principal, context, now, maxDurationDays, database, authorization, abac, config } =
    params;
  const validFrom = new Date(input.validFrom);
  const validUntil = new Date(input.validUntil);

  if (validUntil <= validFrom) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
      message: 'validUntil must be after validFrom.',
    });
  }

  const maxMs = maxDurationDays * 24 * 60 * 60 * 1000;
  if (validUntil.getTime() - validFrom.getTime() > maxMs) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
      message: `Grant duration cannot exceed ${maxDurationDays} days.`,
    });
  }

  const document = await database.document.findUnique({
    where: { id: input.documentId },
    include: {
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true, business_categories: true },
      },
    },
  });

  if (!document) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document was not found.',
    });
  }
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

  if (document.owner_id !== principal.userId) {
    const hasPermission = await authorization.hasPermission(principal, 'ACCESS_GRANT', 'CREATE', {
      targetDepartmentId: document.department_id,
    });
    if (!hasPermission) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.FORBIDDEN,
        message: 'Only the document owner or authorized administrator can grant access.',
      });
    }
  }

  await validateGrantTargetAndSod(database, input, now);

  const currentClassification = document.classification_history[0];
  const documentRank = currentClassification?.classification_levels?.rank ?? 0;

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

  const subjectUserId =
    input.principalType === 'USER' && input.principalUserId
      ? input.principalUserId
      : principal.userId;
  const subjectAttributes = await buildGrantSubjectAttributes(database, subjectUserId, now);
  const resourceAttributes = buildGrantResourceAttributes(document, currentClassification);
  const trustedNetwork = isTrustedClientNetwork(config, context.ip);

  for (const permission of input.permissions) {
    const abacResult = await abac.evaluate({
      resourceType: 'DOCUMENT',
      action: permission as 'VIEW' | 'DOWNLOAD',
      subject: subjectAttributes,
      resource: resourceAttributes,
      environment: {
        currentTime: now.toISOString(),
        ip: context.ip,
        trustedNetwork,
        deviceTrust: false,
        mfa: principal.mfa,
        riskScore: 0,
      },
    });
    if (abacResult.decision === 'DENY') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_ABAC_DENIED,
        message: `ABAC policy denied ${permission} access: ${abacResult.reasonCode}.`,
      });
    }
  }

  return { validFrom, validUntil, maxMs };
}
