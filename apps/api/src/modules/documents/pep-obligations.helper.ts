/**
 * Module: PEP ABAC PDP Evaluation, Obligation Gate & Session Finalization Helper
 * Algorithm: Evaluates ABAC policy decision over `(subject, resource, environment)`, enforces
 *   `REQUIRE_MFA`, `FORBID_DOWNLOAD`, `REQUIRE_WATERMARK`, and `MAX_SESSION_MINUTES` obligations,
 *   and persists context-bound `AccessSession` with bounded-FIFO (10,000) policy cache + audit snapshot.
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AbacService } from '../abac/abac.service.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import {
  buildPepSubjectAttributes,
  resolvePepTrustedNetwork,
  type ActiveSessionPolicy,
} from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface PepPolicyObligationOutcome {
  forbidDownloadObligation: boolean;
  watermarkRequired: boolean;
  expiresAtMs: number | null;
  obligationTypes: string[];
}

/**
 * Algorithm: ABAC PDP Decision & Mandatory Obligation Gate
 */
export async function evaluatePepPolicyAndObligations(params: {
  database: PrismaClient;
  abac: AbacService;
  config: AppConfigService | undefined;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  principal: AuthPrincipal;
  context: RequestContext;
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
    documentRank,
    departmentId,
    documentStatus,
    ownerId,
    categoryCode,
    classRequireWatermark,
    effectiveGrantId,
    deny,
  } = params;

  const subjectAttributes = await buildPepSubjectAttributes(database, principal.userId, now);
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
      trustedNetwork: resolvePepTrustedNetwork(config, context.ip),
      deviceTrust: false,
      mfa: principal.mfa,
      riskScore: 0,
    },
  });

  if (abacResult.decision === 'DENY') {
    await deny(effectiveGrantId, AppErrorCode.POLICY_DENIED, abacResult.reasonCode);
    throw new ForbiddenException({
      errorCode: AppErrorCode.POLICY_DENIED,
      message: `Access denied by policy: ${abacResult.reasonCode}`,
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
  const maxSessionObligation = obligations.find(
    (o): o is Extract<(typeof obligations)[number], { type: 'MAX_SESSION_MINUTES' }> =>
      o.type === 'MAX_SESSION_MINUTES',
  );
  const expiresAtMs =
    maxSessionObligation && typeof maxSessionObligation.minutes === 'number'
      ? now.getTime() + maxSessionObligation.minutes * 60_000
      : null;

  return {
    forbidDownloadObligation,
    watermarkRequired,
    expiresAtMs,
    obligationTypes: obligations.map((o) => o.type),
  };
}

/**
 * Algorithm: Context-Bound AccessSession Creation & Bounded-FIFO (10,000) Policy Snapshot Persistence
 * Inserts `ACTIVE` session row, caches obligation policy in FIFO map, and writes `ACCESS_PERMITTED` audit snapshot.
 */
export async function finalizePermittedAccessSession(params: {
  database: PrismaClient;
  audit: DocumentDeliveryAuditService;
  sessionPolicies: Map<string, ActiveSessionPolicy>;
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
    sessionPolicies,
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
  await database.accessSession.create({
    data: {
      id: sessionId,
      access_grant_id: effectiveGrantId,
      document_version_id: documentVersionId,
      user_id: principal.userId,
      ip_address: context.ip,
      user_agent: context.userAgent ?? null,
      device_fingerprint: deviceFingerprint ?? null,
      status: 'ACTIVE',
      started_at: now,
      last_activity_at: now,
    },
  });

  if (sessionPolicies.size >= 10_000) {
    const oldestKey = sessionPolicies.keys().next().value;
    if (oldestKey) sessionPolicies.delete(oldestKey);
  }
  sessionPolicies.set(sessionId, {
    grantedAction: action,
    forbidDownload: policyOutcome.forbidDownloadObligation,
    expiresAtMs: policyOutcome.expiresAtMs,
  });

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
        expiresAtMs: policyOutcome.expiresAtMs,
        obligations: policyOutcome.obligationTypes.join(','),
      },
    },
    principal,
    context,
  );

  return sessionId;
}
