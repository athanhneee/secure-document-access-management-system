/**
 * Module: PEP ABAC PDP Evaluation, Obligation Gate & Distributed Session Finalization Helper
 * Thuật toán: Thẩm Định Quyết Định ABAC PDP, Cưỡng Chế Nghĩa Vụ & Lưu Bản Chụp Chính Sách Phiên Phân Tán (`DistributedStateService`).
 *   1. Đánh giá chính sách ABAC trên bộ ba `(subject, resource, environment)` và thực thi `REQUIRE_MFA`, `FORBID_DOWNLOAD`, `REQUIRE_WATERMARK`, `MAX_SESSION_MINUTES`.
 *   2. Khởi tạo dòng `AccessSession` trạng thái `ACTIVE` gắn chặt `ip_address` và `user_agent` của người gọi.
 *   3. Lưu bản chụp chính sách phiên vào `DistributedStateService` với TTL bắt buộc có chặn trên `Math.min(maxSessionMinutes ?? 30, 60) * 60_000` (tối đa 60 phút, mặc định 30 phút).
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AbacService } from '../abac/abac.service.js';
import { evaluatePepSessionRisk } from '../abac/session-risk-scorer.helper.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import { normalizeDeliveryClientIp } from './delivery-ticket.helper.js';
import {
  buildPepSubjectAttributes,
  computeBoundedSessionPolicyTtlMs,
  resolvePepTrustedNetwork,
  type ActiveSessionPolicy,
} from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const SESSION_POLICY_NAMESPACE = 'session-policy';

export interface PepPolicyObligationOutcome {
  forbidDownloadObligation: boolean;
  watermarkRequired: boolean;
  maxSessionMinutes: number | null;
  expiresAtMs: number | null;
  obligationTypes: string[];
  riskScore: number;
  riskFactors: string[];
}

/**
 * Thuật toán: Thẩm Định Quyết Định ABAC PDP & Cổng Nghĩa Vụ Bắt Buộc (`evaluatePepPolicyAndObligations`)
 */
export async function evaluatePepPolicyAndObligations(params: {
  database: PrismaClient;
  abac: AbacService;
  config: AppConfigService | undefined;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  principal: AuthPrincipal;
  context: RequestContext;
  deviceFingerprint?: string | undefined;
  documentRank: number;
  departmentId: bigint | null | undefined;
  documentStatus: string;
  ownerId: bigint;
  categoryCode: string | null;
  classRequireWatermark: boolean;
  effectiveGrantId: string;
  deny: (grantId: string | null, reasonCode: string, reasonMessage: string) => Promise<void>;
}): Promise<PepPolicyObligationOutcome> {
  const {
    database,
    abac,
    config,
    action,
    now,
    principal,
    context,
    deviceFingerprint,
    documentRank,
    departmentId,
    documentStatus,
    ownerId,
    categoryCode,
    classRequireWatermark,
    effectiveGrantId,
    deny,
  } = params;

  const trustedNetwork = resolvePepTrustedNetwork(config, context.ip);
  const [subjectAttributes, riskAssessment] = await Promise.all([
    buildPepSubjectAttributes(database, principal.userId, now),
    evaluatePepSessionRisk({
      database,
      principal,
      context,
      trustedNetwork,
      classificationRank: documentRank,
      deviceFingerprint,
      now,
    }),
  ]);
  const abacResult = await abac.evaluate({
    resourceType: 'DOCUMENT',
    action,
    subject: subjectAttributes,
    resource: {
      classificationRank: documentRank,
      departmentId: departmentId?.toString() ?? null,
      ownerId: ownerId.toString(),
      category: categoryCode,
      status: documentStatus,
    },
    environment: {
      currentTime: now.toISOString(),
      ip: context.ip,
      trustedNetwork,
      deviceTrust: riskAssessment.deviceTrust,
      mfa: principal.mfa,
      riskScore: riskAssessment.riskScore,
    },
  });

  if (abacResult.decision === 'DENY') {
    if (abacResult.reasonCode === 'STEP_UP_MFA_REQUIRED' && !principal.mfa) {
      await deny(
        effectiveGrantId,
        AppErrorCode.STEP_UP_MFA_REQUIRED,
        'Access policy requires multi-factor authentication for this document.',
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.STEP_UP_MFA_REQUIRED,
        message: 'Access policy requires multi-factor authentication for this document.',
        details: {
          reasonCode: abacResult.reasonCode,
          riskScore: riskAssessment.riskScore,
        },
      });
    }

    const missingAttributes: string[] = [];
    if (abacResult.reasonCode === 'MISSING_REQUIRED_ATTRIBUTE') {
      if (subjectAttributes.departmentId === null) missingAttributes.push('SUBJECT_DEPARTMENT');
      if (subjectAttributes.clearanceRank === null) missingAttributes.push('CLEARANCE_LEVEL');
      if (subjectAttributes.employmentStatus === null) missingAttributes.push('EMPLOYMENT_STATUS');
      if (departmentId === null || departmentId === undefined)
        missingAttributes.push('RESOURCE_DEPARTMENT');
      if (categoryCode === null) missingAttributes.push('RESOURCE_CATEGORY');
    }
    const missingSuffix = missingAttributes.length > 0 ? ` (${missingAttributes.join(', ')})` : '';
    const denialSummary = `${abacResult.reasonCode}${missingSuffix}`;
    await deny(effectiveGrantId, AppErrorCode.POLICY_DENIED, denialSummary);
    throw new ForbiddenException({
      errorCode: AppErrorCode.POLICY_DENIED,
      message: `Access denied by policy: ${denialSummary}`,
      details: {
        reasonCode: abacResult.reasonCode,
        riskScore: riskAssessment.riskScore,
        ...(riskAssessment.factors.length > 0 ? { riskFactors: riskAssessment.factors } : {}),
        ...(missingAttributes.length > 0 ? { missingAttributes } : {}),
      },
    });
  }

  const obligations = abacResult.obligations ?? [];
  if (obligations.some((o) => o.type === 'REQUIRE_MFA') && !principal.mfa) {
    await deny(
      effectiveGrantId,
      AppErrorCode.STEP_UP_MFA_REQUIRED,
      'Policy obligation requires multi-factor authentication.',
    );
    throw new ForbiddenException({
      errorCode: AppErrorCode.STEP_UP_MFA_REQUIRED,
      message: 'Policy obligation requires multi-factor authentication.',
    });
  }

  const forbidDownloadObligation = obligations.some((o) => o.type === 'FORBID_DOWNLOAD');
  if (action === 'DOWNLOAD' && forbidDownloadObligation) {
    await deny(
      effectiveGrantId,
      AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      'Policy obligation forbids download.',
    );
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Policy obligation forbids downloading this document.',
    });
  }

  const watermarkRequired =
    classRequireWatermark || obligations.some((o) => o.type === 'REQUIRE_WATERMARK');
  const maxMinutesValues = obligations
    .filter(
      (o): o is Extract<(typeof obligations)[number], { type: 'MAX_SESSION_MINUTES' }> =>
        o.type === 'MAX_SESSION_MINUTES' && typeof o.minutes === 'number' && o.minutes > 0,
    )
    .map((o) => o.minutes);
  const maxSessionMinutes = maxMinutesValues.length > 0 ? Math.min(...maxMinutesValues) : null;
  const expiresAtMs =
    maxSessionMinutes !== null ? now.getTime() + maxSessionMinutes * 60_000 : null;

  return {
    forbidDownloadObligation,
    watermarkRequired,
    maxSessionMinutes,
    expiresAtMs,
    obligationTypes: obligations.map((o) => o.type),
    riskScore: riskAssessment.riskScore,
    riskFactors: riskAssessment.factors,
  };
}

/**
 * Thuật toán: Khởi Tạo `AccessSession` Gắn Ngữ Cảnh & Ghi Đệm Chính Sách Phiên Có TTL Hữu Hạn (`finalizePermittedAccessSession`)
 */
export async function finalizePermittedAccessSession(params: {
  database: PrismaClient;
  audit: DocumentDeliveryAuditService;
  stateStore: DistributedStateService;
  documentId: string;
  effectiveGrantId: string;
  documentVersionId: bigint;
  versionNo: number;
  action: 'VIEW' | 'DOWNLOAD';
  deviceFingerprint: string | undefined;
  now: Date;
  principal: AuthPrincipal;
  context: RequestContext;
  policyOutcome: PepPolicyObligationOutcome;
}): Promise<string> {
  const {
    database,
    audit,
    stateStore,
    documentId,
    effectiveGrantId,
    documentVersionId,
    versionNo,
    action,
    deviceFingerprint,
    now,
    principal,
    context,
    policyOutcome,
  } = params;

  const sessionId = randomUUID();
  const normalizedIp = normalizeDeliveryClientIp(context.ip);
  const normalizedUa = context.userAgent?.trim() || null;

  await database.accessSession.create({
    data: {
      id: sessionId,
      access_grant_id: effectiveGrantId,
      document_version_id: documentVersionId,
      user_id: principal.userId,
      ip_address: context.ip,
      user_agent: normalizedUa,
      device_fingerprint: deviceFingerprint ?? null,
      status: 'ACTIVE',
      started_at: now,
      last_activity_at: now,
    },
  });

  const policyRecord: ActiveSessionPolicy = {
    grantedAction: action,
    forbidDownload: policyOutcome.forbidDownloadObligation,
    expiresAtMs: policyOutcome.expiresAtMs,
    maxSessionMinutes: policyOutcome.maxSessionMinutes,
    ipAddress: normalizedIp,
    userAgent: normalizedUa,
  };
  const ttlMs = computeBoundedSessionPolicyTtlMs(policyOutcome.maxSessionMinutes);
  await stateStore.putEphemeral(SESSION_POLICY_NAMESPACE, sessionId, policyRecord, ttlMs);

  await audit.record(
    {
      action: 'ACCESS_PERMITTED',
      outcome: 'SUCCESS',
      documentId,
      sessionId,
      objectId: effectiveGrantId,
      details: {
        action,
        grantedAction: action,
        versionNo,
        watermarkRequired: policyOutcome.watermarkRequired,
        forbidDownload: policyOutcome.forbidDownloadObligation,
        maxSessionMinutes: policyOutcome.maxSessionMinutes,
        expiresAtMs: policyOutcome.expiresAtMs,
        obligations: policyOutcome.obligationTypes.join(','),
        riskScore: policyOutcome.riskScore,
        ...(policyOutcome.riskFactors.length > 0
          ? { riskFactors: policyOutcome.riskFactors.join(',') }
          : {}),
      },
    },
    principal,
    context,
  );

  return sessionId;
}
