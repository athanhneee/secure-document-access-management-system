/**
 * Module: Fail-Closed Distributed Session Policy Resolver & Multi-Replica Obligation Re-Hydrator
 * Thuật toán: Thẩm Định Trạng Thái Phiên CSDL Thời Gian Thực & Khôi Phục Nghĩa Vụ ABAC Đa Bản Sao (`resolveAndEnforceSessionPolicy`).
 *   1. Xác nhận trực tiếp trong CSDL rằng `AccessSession.status === 'ACTIVE'` để phiên bị chấm dứt/thu hồi bị từ chối tức thì trên mọi bản sao API.
 *   2. Ràng buộc địa chỉ `ipAddress` và `userAgent` (khi có) giữa phiên gốc và yêu cầu hiện hành nhằm ngăn đánh cắp phiên.
 *   3. Đọc chính sách phiên từ `DistributedStateService`; khi trượt cache thì khôi phục từ `audit_logs` (`ACCESS_PERMITTED`) kết hợp tái đánh giá ABAC PDP và ghi lại với TTL hữu hạn (`<= 60` phút).
 */
import { ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AbacService } from '../abac/abac.service.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { normalizeDeliveryClientIp } from './delivery-ticket.helper.js';
import {
  buildPepSubjectAttributes,
  computeBoundedSessionPolicyTtlMs,
  resolvePepTrustedNetwork,
  type ActiveSessionPolicy,
} from './pep-context-builder.js';
import { SESSION_POLICY_NAMESPACE } from './pep-obligations.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SessionRecordForPolicyCheck {
  id: string;
  status?: string | null | undefined;
  user_id?: bigint | undefined;
  ip_address?: string | null | undefined;
  user_agent?: string | null | undefined;
  started_at?: Date | string | null;
  document_versions?: {
    document_id: string;
    document?: {
      id?: string;
      department_id?: bigint | null;
      status?: string;
      owner_id?: bigint;
      classification_history?: Array<{
        classification_levels?: { rank?: number | null } | null;
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

  return { grantedAction, forbidDownload, expiresAtMs, maxSessionMinutes };
}

/**
 * Thuật toán: Thẩm Định Trạng Thái `ACTIVE` Trong CSDL, Ràng Buộc IP/UA & Cưỡng Chế Nghĩa Vụ Phiên Fail-Closed
 */
export async function resolveAndEnforceSessionPolicy(
  params: ResolveSessionPolicyParams,
): Promise<ActiveSessionPolicy> {
  const { session, requiredAction, principal, context, now, database, abac } = params;
  const stateStore = params.stateStore ?? new DistributedStateService(params.config);

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

  let policy = await stateStore.getJson<ActiveSessionPolicy>(SESSION_POLICY_NAMESPACE, session.id);

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
    const doc = session.document_versions?.document;
    if (
      typeof abac?.evaluate === 'function' &&
      typeof database?.userAttributeAssignment?.findFirst === 'function' &&
      doc &&
      doc.owner_id !== undefined &&
      typeof doc.status === 'string'
    ) {
      const subjectAttributes = await buildPepSubjectAttributes(database, principal.userId, now);
      const currentClass = doc.classification_history?.[0];
      const evalAction = persistedPolicy ? persistedPolicy.grantedAction : requiredAction;
      const abacResult = await abac.evaluate({
        resourceType: 'DOCUMENT',
        action: evalAction,
        subject: subjectAttributes,
        resource: {
          classificationRank: currentClass?.classification_levels?.rank ?? 0,
          departmentId: doc.department_id?.toString() ?? null,
          ownerId: doc.owner_id.toString(),
          category: currentClass?.business_categories?.code ?? null,
          status: doc.status,
        },
        environment: {
          currentTime: now.toISOString(),
          ip: context.ip,
          trustedNetwork: resolvePepTrustedNetwork(params.config, context.ip),
          deviceTrust: false,
          mfa: principal.mfa,
          riskScore: 0,
        },
      });

      if (abacResult.decision === 'DENY') {
        throw new ForbiddenException({
          errorCode: AppErrorCode.POLICY_DENIED,
          message: `Access denied by active ABAC policy: ${abacResult.reasonCode}`,
        });
      }

      const obligations = abacResult.obligations ?? [];
      if (obligations.some((o) => o.type === 'REQUIRE_MFA') && !principal.mfa) {
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
        expiresAtMs: minMinutes !== null ? anchorMs + minMinutes * 60_000 : null,
        maxSessionMinutes: minMinutes,
      };
    }

    if (!persistedPolicy && !livePolicy) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Unable to verify session ABAC policy obligations; failing closed.',
      });
    }

    const expiryCandidates = [persistedPolicy?.expiresAtMs, livePolicy?.expiresAtMs].filter(
      (value): value is number => typeof value === 'number' && Number.isFinite(value),
    );
    const minuteCandidates = [
      persistedPolicy?.maxSessionMinutes,
      livePolicy?.maxSessionMinutes,
    ].filter((value): value is number => typeof value === 'number' && value > 0);
    const resolvedMaxMinutes = minuteCandidates.length > 0 ? Math.min(...minuteCandidates) : null;

    policy = {
      grantedAction:
        persistedPolicy?.grantedAction ?? livePolicy?.grantedAction ?? ('VIEW' as const),
      forbidDownload: Boolean(persistedPolicy?.forbidDownload || livePolicy?.forbidDownload),
      expiresAtMs: expiryCandidates.length > 0 ? Math.min(...expiryCandidates) : null,
      maxSessionMinutes: resolvedMaxMinutes,
      ipAddress: normalizeDeliveryClientIp(liveDbIp),
      userAgent: liveDbUa?.trim() || null,
    };

    const cacheTtlMs = computeBoundedSessionPolicyTtlMs(resolvedMaxMinutes);
    await stateStore.putEphemeral(SESSION_POLICY_NAMESPACE, session.id, policy, cacheTtlMs);
  }

  const boundIp = normalizeDeliveryClientIp(liveDbIp ?? policy.ipAddress);
  const callerIp = normalizeDeliveryClientIp(context?.ip);
  if (boundIp && callerIp && boundIp !== callerIp) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Client IP does not match bound access session.',
    });
  }
  const boundUa = (liveDbUa ?? policy.userAgent)?.trim() || null;
  const callerUa = context?.userAgent?.trim() || null;
  if (boundUa && callerUa && boundUa !== callerUa) {
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
