/**
 * Module: Fail-Closed Distributed Session Policy Resolver & Multi-Replica Obligation Re-Hydrator
 * Thuật toán: Thẩm Định Trạng Thái Phiên CSDL Thời Gian Thực, Ràng Buộc IP/UA Một Chiều & Tái Đánh Giá ABAC Khi Đổi Chính Sách/Thuộc Tính (`BUG-057`).
 *   1. Xác nhận trực tiếp trong CSDL rằng `AccessSession.status === 'ACTIVE'` để phiên bị chấm dứt/thu hồi bị từ chối tức thì trên mọi bản sao API.
 *   2. Ràng buộc một chiều fail-closed địa chỉ `ipAddress` và `userAgent` khi phiên đã neo (`boundUa && (!callerUa || boundUa !== callerUa)`).
 *   3. Đối chiếu `policyVersion`, `abacEpoch`, `userEpoch` và ảnh chụp thuộc tính chủ thể (`user.status`, `EMPLOYMENT_STATUS`, `CLEARANCE_LEVEL`) — khi lệch thì tái đánh giá `abac.evaluate()` ngay lập tức nhưng giữ nguyên mốc hết hạn `Math.min` neo theo `session.started_at`.
 */
import { ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AbacService } from '../abac/abac.service.js';
import { evaluatePepSessionRisk } from '../abac/session-risk-scorer.helper.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { normalizeDeliveryClientIp } from './delivery-ticket.helper.js';
import {
  buildPepSubjectAttributes,
  computeBoundedSessionPolicyTtlMs,
  hasPrivilegedNonBusinessCapability,
  isRestrictedNonBusinessRole,
  resolvePepTrustedNetwork,
  type ActiveSessionPolicy,
  type SessionResourcePolicySnapshot,
  type SessionSubjectPolicySnapshot,
} from './pep-context-builder.js';
import { SESSION_POLICY_NAMESPACE } from './pep-obligations.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SessionRecordForPolicyCheck {
  id: string;
  status?: string | null | undefined;
  user_id?: bigint | undefined;
  ip_address?: string | null | undefined;
  user_agent?: string | null | undefined;
  device_fingerprint?: string | null | undefined;
  started_at?: Date | string | null;
  document_versions?: {
    document_id: string;
    document?: {
      id?: string;
      department_id?: bigint | null;
      status?: string;
      owner_id?: bigint;
      classification_history?: Array<{
        classification_levels?: {
          rank?: number | null;
          require_watermark?: boolean | null;
        } | null;
        business_categories?: { code?: string | null } | null;
      }>;
    } | null;
  } | null;
}

export interface ResolveSessionPolicyParams {
  session: SessionRecordForPolicyCheck;
  requiredAction: 'VIEW' | 'DOWNLOAD';
  principal: AuthPrincipal;
  context: RequestContext;
  now: Date;
  stateStore?: DistributedStateService | undefined;
  database: PrismaClient;
  abac?: AbacService | undefined;
  config?: AppConfigService | undefined;
}

function parsePersistedSessionPolicy(
  details: unknown,
  startedAtMs: number | null,
): ActiveSessionPolicy | null {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return null;
  const record = details as Record<string, unknown>;
  const rawAction = record['grantedAction'] ?? record['action'];
  const grantedAction: 'VIEW' | 'DOWNLOAD' | null =
    rawAction === 'DOWNLOAD' ? 'DOWNLOAD' : rawAction === 'VIEW' ? 'VIEW' : null;
  if (!grantedAction) return null;

  const obligationsCsv = typeof record['obligations'] === 'string' ? record['obligations'] : '';
  const obligationTokens = obligationsCsv
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);
  const forbidDownload =
    record['forbidDownload'] === true || obligationTokens.includes('FORBID_DOWNLOAD');
  const watermarkRequired =
    record['watermarkRequired'] === true || obligationTokens.includes('REQUIRE_WATERMARK');
  const maxSessionMinutes =
    typeof record['maxSessionMinutes'] === 'number' &&
    Number.isFinite(record['maxSessionMinutes']) &&
    record['maxSessionMinutes'] > 0
      ? record['maxSessionMinutes']
      : null;

  let expiresAtMs: number | null = null;
  if (typeof record['expiresAtMs'] === 'number' && Number.isFinite(record['expiresAtMs'])) {
    expiresAtMs = record['expiresAtMs'];
  } else if (maxSessionMinutes !== null && startedAtMs !== null) {
    expiresAtMs = startedAtMs + maxSessionMinutes * 60_000;
  }

  return { grantedAction, forbidDownload, watermarkRequired, expiresAtMs, maxSessionMinutes };
}

/**
 * Thuật toán: Thẩm Định Trạng Thái `ACTIVE` Trong CSDL, Ràng Buộc IP/UA Một Chiều & Cưỡng Chế Nghĩa Vụ Phiên Fail-Closed (`BUG-057`)
 */
export async function resolveAndEnforceSessionPolicy(
  params: ResolveSessionPolicyParams,
): Promise<ActiveSessionPolicy> {
  const { session, requiredAction, principal, context, now, database, abac } = params;
  const stateStore = params.stateStore ?? new DistributedStateService(params.config);

  if (
    isRestrictedNonBusinessRole(principal) ||
    (await hasPrivilegedNonBusinessCapability(database, principal, now))
  ) {
    await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message:
        'Privileged administrative, security, and auditor roles cannot access document sessions.',
    });
  }

  let liveDbIp: string | null | undefined = session.ip_address;
  let liveDbUa: string | null | undefined = session.user_agent;

  if (typeof database?.accessSession?.findUnique === 'function') {
    const dbSession = await database.accessSession.findUnique({ where: { id: session.id } });
    if (!dbSession || dbSession.status !== 'ACTIVE') {
      await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: 'Access session is no longer active.',
      });
    }
    if (dbSession.user_id !== undefined && dbSession.user_id !== principal.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_USER_MISMATCH,
        message: 'Session does not belong to the calling user.',
      });
    }
    liveDbIp = (dbSession as { ip_address?: string | null }).ip_address ?? liveDbIp;
    liveDbUa = (dbSession as { user_agent?: string | null }).user_agent ?? liveDbUa;
  } else if (session.status !== undefined && session.status !== 'ACTIVE') {
    await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
    throw new ForbiddenException({
      errorCode: AppErrorCode.SESSION_TERMINATED,
      message: 'Access session is no longer active.',
    });
  }

  const [currentAbacEpoch, currentUserEpoch, currentPolicyVersion] = await Promise.all([
    typeof stateStore.getNamespaceEpoch === 'function'
      ? stateStore.getNamespaceEpoch('abac-policy').catch(() => 0)
      : Promise.resolve(0),
    typeof stateStore.getNamespaceEpoch === 'function'
      ? stateStore.getNamespaceEpoch(`rbac-user:${principal.userId.toString()}`).catch(() => 0)
      : Promise.resolve(0),
    typeof abac?.getCurrentPolicyVersion === 'function'
      ? abac.getCurrentPolicyVersion().catch(() => null)
      : Promise.resolve(null),
  ]);

  let liveSubjectAttrs: Awaited<ReturnType<typeof buildPepSubjectAttributes>> | null = null;
  if (typeof database?.userAttributeAssignment?.findFirst === 'function') {
    liveSubjectAttrs = await buildPepSubjectAttributes(database, principal.userId, now);
    if (
      liveSubjectAttrs.employmentStatus === 'LOCKED' ||
      liveSubjectAttrs.employmentStatus === 'DISABLED'
    ) {
      await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Subject account status is no longer eligible for document access.',
      });
    }
  } else if (typeof database?.user?.findUnique === 'function') {
    const liveUser = await database.user.findUnique({
      where: { id: principal.userId },
      select: { status: true },
    });
    if (liveUser && liveUser.status !== 'ACTIVE') {
      await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Subject account is no longer active.',
      });
    }
  }

  const docForSnapshot = session.document_versions?.document;
  const liveResourceSnapshot: SessionResourcePolicySnapshot | null =
    docForSnapshot && typeof docForSnapshot.status === 'string'
      ? {
          classificationRank:
            docForSnapshot.classification_history?.[0]?.classification_levels?.rank ?? 0,
          category: docForSnapshot.classification_history?.[0]?.business_categories?.code ?? null,
          departmentId: docForSnapshot.department_id?.toString() ?? null,
          status: docForSnapshot.status,
        }
      : null;

  const cachedPolicy = await stateStore.getJson<ActiveSessionPolicy>(
    SESSION_POLICY_NAMESPACE,
    session.id,
  );
  let policy: ActiveSessionPolicy | null =
    cachedPolicy && typeof cachedPolicy.watermarkRequired === 'boolean' ? cachedPolicy : null;
  let cacheWasInvalidated = false;

  if (policy) {
    const policyEpochChanged =
      policy.abacEpoch !== undefined && policy.abacEpoch !== currentAbacEpoch;
    const userEpochChanged =
      policy.userEpoch !== undefined && policy.userEpoch !== currentUserEpoch;
    const policyVersionChanged =
      policy.policyVersion !== undefined &&
      policy.policyVersion !== null &&
      currentPolicyVersion !== null &&
      policy.policyVersion !== currentPolicyVersion;
    const subjectSnapshotChanged =
      Boolean(policy.subjectSnapshot) &&
      Boolean(liveSubjectAttrs) &&
      (policy.subjectSnapshot!.employmentStatus !== liveSubjectAttrs!.employmentStatus ||
        policy.subjectSnapshot!.clearanceRank !== liveSubjectAttrs!.clearanceRank ||
        policy.subjectSnapshot!.departmentId !== liveSubjectAttrs!.departmentId);
    const resourceSnapshotChanged =
      Boolean(policy.resourceSnapshot) &&
      Boolean(liveResourceSnapshot) &&
      (policy.resourceSnapshot!.classificationRank !== liveResourceSnapshot!.classificationRank ||
        policy.resourceSnapshot!.category !== liveResourceSnapshot!.category ||
        policy.resourceSnapshot!.departmentId !== liveResourceSnapshot!.departmentId ||
        policy.resourceSnapshot!.status !== liveResourceSnapshot!.status);

    if (
      policyEpochChanged ||
      userEpochChanged ||
      policyVersionChanged ||
      subjectSnapshotChanged ||
      resourceSnapshotChanged
    ) {
      policy = null;
      cacheWasInvalidated = true;
    }
  }

  if (!policy) {
    const rawStartMs = session.started_at ? new Date(session.started_at).getTime() : null;
    const validStartedAtMs = rawStartMs !== null && Number.isFinite(rawStartMs) ? rawStartMs : null;

    let persistedPolicy: ActiveSessionPolicy | null = null;
    if (typeof database?.auditLog?.findFirst === 'function') {
      const auditEntry = await database.auditLog.findFirst({
        where: { access_session_id: session.id, action: 'ACCESS_PERMITTED', outcome: 'SUCCESS' },
        orderBy: { occurred_at: 'desc' },
      });
      if (auditEntry) {
        persistedPolicy = parsePersistedSessionPolicy(auditEntry.details, validStartedAtMs);
      }
    }

    let livePolicy: ActiveSessionPolicy | null = null;
    let evaluatedPolicyVersion: string | null = currentPolicyVersion;
    let evaluatedSubjectSnapshot: SessionSubjectPolicySnapshot | undefined = liveSubjectAttrs
      ? {
          employmentStatus: liveSubjectAttrs.employmentStatus,
          clearanceRank: liveSubjectAttrs.clearanceRank,
          departmentId: liveSubjectAttrs.departmentId,
        }
      : cachedPolicy?.subjectSnapshot;

    const doc = session.document_versions?.document;
    if (
      typeof abac?.evaluate === 'function' &&
      typeof database?.userAttributeAssignment?.findFirst === 'function' &&
      doc &&
      doc.owner_id !== undefined &&
      typeof doc.status === 'string'
    ) {
      const currentClass = doc.classification_history?.[0];
      const classificationRank = currentClass?.classification_levels?.rank ?? 0;
      const trustedNetwork = resolvePepTrustedNetwork(params.config, context.ip);
      const [subjectAttributes, riskAssessment] = await Promise.all([
        liveSubjectAttrs
          ? Promise.resolve(liveSubjectAttrs)
          : buildPepSubjectAttributes(database, principal.userId, now),
        evaluatePepSessionRisk({
          database,
          principal,
          context,
          trustedNetwork,
          classificationRank,
          deviceFingerprint: session.device_fingerprint,
          now,
        }),
      ]);
      evaluatedSubjectSnapshot = {
        employmentStatus: subjectAttributes.employmentStatus,
        clearanceRank: subjectAttributes.clearanceRank,
        departmentId: subjectAttributes.departmentId,
      };
      const evalAction =
        persistedPolicy?.grantedAction ?? cachedPolicy?.grantedAction ?? requiredAction;
      const abacResult = await abac.evaluate({
        resourceType: 'DOCUMENT',
        action: evalAction,
        subject: subjectAttributes,
        resource: {
          classificationRank,
          departmentId: doc.department_id?.toString() ?? null,
          ownerId: doc.owner_id.toString(),
          category: currentClass?.business_categories?.code ?? null,
          status: doc.status,
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
      evaluatedPolicyVersion = abacResult.policyVersion ?? currentPolicyVersion;

      if (abacResult.decision === 'DENY') {
        await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
        if (abacResult.reasonCode === 'STEP_UP_MFA_REQUIRED' && !principal.mfa) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.STEP_UP_MFA_REQUIRED,
            message: 'Access policy requires multi-factor authentication for this document.',
          });
        }
        throw new ForbiddenException({
          errorCode: AppErrorCode.POLICY_DENIED,
          message: `Access denied by active ABAC policy: ${abacResult.reasonCode}`,
        });
      }

      const obligations = abacResult.obligations ?? [];
      if (obligations.some((o) => o.type === 'REQUIRE_MFA') && !principal.mfa) {
        await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
        throw new ForbiddenException({
          errorCode: AppErrorCode.STEP_UP_MFA_REQUIRED,
          message: 'Policy obligation requires multi-factor authentication.',
        });
      }

      const maxMinutesList = obligations
        .filter(
          (o): o is Extract<(typeof obligations)[number], { type: 'MAX_SESSION_MINUTES' }> =>
            o.type === 'MAX_SESSION_MINUTES' && typeof o.minutes === 'number' && o.minutes > 0,
        )
        .map((o) => o.minutes);
      const minMinutes = maxMinutesList.length > 0 ? Math.min(...maxMinutesList) : null;
      const anchorMs = validStartedAtMs ?? now.getTime();
      livePolicy = {
        grantedAction: evalAction,
        forbidDownload: obligations.some((o) => o.type === 'FORBID_DOWNLOAD'),
        watermarkRequired:
          currentClass?.classification_levels?.require_watermark === true ||
          obligations.some((o) => o.type === 'REQUIRE_WATERMARK'),
        expiresAtMs: minMinutes !== null ? anchorMs + minMinutes * 60_000 : null,
        maxSessionMinutes: minMinutes,
      };
    }

    // HIGH-03: Nếu bộ đệm chính sách phiên vừa bị vô hiệu hóa do thay đổi chính sách/chủ thể/tài liệu nhưng không thể tái đánh giá ABAC trực tiếp, bắt buộc từ chối Fail-Closed tuyệt đối không hợp thức hóa lại cachedPolicy cũ.
    if (cacheWasInvalidated && !livePolicy) {
      await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Session ABAC policy invalidated and could not be re-evaluated; failing closed.',
      });
    }

    if (!persistedPolicy && !livePolicy && !cachedPolicy) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Unable to verify session ABAC policy obligations; failing closed.',
      });
    }

    const evaluatedResourceSnapshot: SessionResourcePolicySnapshot | undefined =
      liveResourceSnapshot ?? cachedPolicy?.resourceSnapshot;

    const expiryCandidates = [
      cachedPolicy?.expiresAtMs,
      persistedPolicy?.expiresAtMs,
      livePolicy?.expiresAtMs,
    ].filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
    const minuteCandidates = [
      cachedPolicy?.maxSessionMinutes,
      persistedPolicy?.maxSessionMinutes,
      livePolicy?.maxSessionMinutes,
    ].filter((value): value is number => typeof value === 'number' && value > 0);
    const resolvedMaxMinutes = minuteCandidates.length > 0 ? Math.min(...minuteCandidates) : null;

    policy = {
      grantedAction:
        persistedPolicy?.grantedAction ??
        cachedPolicy?.grantedAction ??
        livePolicy?.grantedAction ??
        ('VIEW' as const),
      forbidDownload: Boolean(
        cachedPolicy?.forbidDownload ||
        persistedPolicy?.forbidDownload ||
        livePolicy?.forbidDownload,
      ),
      watermarkRequired: Boolean(
        cachedPolicy?.watermarkRequired ||
        persistedPolicy?.watermarkRequired ||
        livePolicy?.watermarkRequired,
      ),
      expiresAtMs: expiryCandidates.length > 0 ? Math.min(...expiryCandidates) : null,
      maxSessionMinutes: resolvedMaxMinutes,
      ipAddress: normalizeDeliveryClientIp(liveDbIp ?? cachedPolicy?.ipAddress),
      userAgent: (liveDbUa ?? cachedPolicy?.userAgent)?.trim() || null,
      policyVersion: evaluatedPolicyVersion,
      abacEpoch: currentAbacEpoch,
      userEpoch: currentUserEpoch,
      ...(evaluatedSubjectSnapshot ? { subjectSnapshot: evaluatedSubjectSnapshot } : {}),
      ...(evaluatedResourceSnapshot ? { resourceSnapshot: evaluatedResourceSnapshot } : {}),
    };

    const cacheTtlMs = computeBoundedSessionPolicyTtlMs(resolvedMaxMinutes);
    await stateStore.putEphemeral(SESSION_POLICY_NAMESPACE, session.id, policy, cacheTtlMs);
  }

  const boundIp = normalizeDeliveryClientIp(liveDbIp ?? policy.ipAddress);
  const callerIp = normalizeDeliveryClientIp(context?.ip);
  if (boundIp && (!callerIp || boundIp !== callerIp)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Client IP does not match bound access session.',
    });
  }
  const boundUa = (liveDbUa ?? policy.userAgent)?.trim() || null;
  const callerUa = context?.userAgent?.trim() || null;
  if (boundUa && (!callerUa || boundUa !== callerUa)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Client User-Agent does not match bound access session.',
    });
  }

  if (policy.expiresAtMs !== null && now.getTime() > policy.expiresAtMs) {
    await stateStore.deleteKey(SESSION_POLICY_NAMESPACE, session.id);
    throw new ForbiddenException({
      errorCode: AppErrorCode.SESSION_EXPIRED,
      message: 'Access session exceeded maximum policy duration.',
    });
  }

  if (
    requiredAction === 'DOWNLOAD' &&
    (policy.forbidDownload || policy.grantedAction !== 'DOWNLOAD')
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Session does not permit downloading this document.',
    });
  }

  return policy;
}
