/**
 * Module: Fail-Closed Session Policy Resolver & Multi-Replica Obligation Re-Hydrator
 * Algorithm / Thuật toán: Khôi Phục & Cưỡng Chế Nghĩa Vụ Phiên ABAC Theo Cơ Chế Đóng An Toàn (Fail-Closed Session Obligation Re-Hydration)
 * Mục đích: Đảm bảo các nghĩa vụ `FORBID_DOWNLOAD` và `MAX_SESSION_MINUTES` luôn được thực thi nghiêm ngặt ngay cả khi API khởi động lại,
 *   bộ nhớ đệm FIFO trục xuất mục cũ, hoặc yêu cầu rơi sang container/replica khác.
 * Cơ chế hoạt động:
 *   1. Kiểm tra bảng băm `sessionPolicies` trong bộ nhớ tiến trình; nếu trúng cache thì dùng ngay để kiểm tra hạn phiên và quyền tải xuống.
 *   2. Khi trượt cache (cache miss): khôi phục bản chụp chính sách lúc cấp phiên từ `audit_logs` (`ACCESS_PERMITTED`) kết hợp tái thẩm định
 *      động cơ ABAC thời gian thực neo theo mốc `session.started_at`, lấy giao chặt nhất của các ràng buộc.
 *   3. Nếu không thể xác minh chính sách phiên từ cả hai nguồn (Fail-Closed), lập tức từ chối bằng `ForbiddenException` thay vì bỏ qua kiểm tra.
 */
import { ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AbacService } from '../abac/abac.service.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import {
  buildPepSubjectAttributes,
  resolvePepTrustedNetwork,
  type ActiveSessionPolicy,
} from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SessionRecordForPolicyCheck {
  id: string;
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
  sessionPolicies: Map<string, ActiveSessionPolicy>;
  database: PrismaClient;
  abac?: AbacService | undefined;
  config?: AppConfigService | undefined;
}

function parsePersistedSessionPolicy(
  details: unknown,
  startedAtMs: number | null,
): ActiveSessionPolicy | null {
  if (!details || typeof details !== 'object' || Array.isArray(details)) {
    return null;
  }
  const record = details as Record<string, unknown>;
  const rawAction = record['grantedAction'] ?? record['action'];
  const grantedAction: 'VIEW' | 'DOWNLOAD' | null =
    rawAction === 'DOWNLOAD' ? 'DOWNLOAD' : rawAction === 'VIEW' ? 'VIEW' : null;
  if (!grantedAction) {
    return null;
  }

  const obligationsCsv = typeof record['obligations'] === 'string' ? record['obligations'] : '';
  const obligationTokens = obligationsCsv
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);
  const forbidDownload =
    record['forbidDownload'] === true || obligationTokens.includes('FORBID_DOWNLOAD');

  let expiresAtMs: number | null = null;
  if (typeof record['expiresAtMs'] === 'number' && Number.isFinite(record['expiresAtMs'])) {
    expiresAtMs = record['expiresAtMs'];
  } else if (
    typeof record['maxSessionMinutes'] === 'number' &&
    Number.isFinite(record['maxSessionMinutes']) &&
    startedAtMs !== null
  ) {
    expiresAtMs = startedAtMs + record['maxSessionMinutes'] * 60_000;
  }

  return {
    grantedAction,
    forbidDownload,
    expiresAtMs,
  };
}

/**
 * Algorithm / Thuật toán: Thẩm Định & Cưỡng Chế Chính Sách Phiên Không Trạng Thái Dự Phòng (Fail-Closed Session Policy Enforcement)
 */
export async function resolveAndEnforceSessionPolicy(
  params: ResolveSessionPolicyParams,
): Promise<ActiveSessionPolicy> {
  const { session, requiredAction, principal, context, now, sessionPolicies, database, abac } =
    params;

  let policy = sessionPolicies.get(session.id);

  if (!policy) {
    const startedAtMs = session.started_at ? new Date(session.started_at).getTime() : null;
    const validStartedAtMs =
      startedAtMs !== null && Number.isFinite(startedAtMs) ? startedAtMs : null;

    let persistedPolicy: ActiveSessionPolicy | null = null;
    if (typeof database?.auditLog?.findFirst === 'function') {
      const auditEntry = await database.auditLog.findFirst({
        where: {
          access_session_id: session.id,
          action: 'ACCESS_PERMITTED',
          outcome: 'SUCCESS',
        },
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
      const documentRank = currentClass?.classification_levels?.rank ?? 0;
      const categoryCode = currentClass?.business_categories?.code ?? null;
      const evalAction = persistedPolicy ? persistedPolicy.grantedAction : requiredAction;

      const abacResult = await abac.evaluate({
        resourceType: 'DOCUMENT',
        action: evalAction,
        subject: subjectAttributes,
        resource: {
          classificationRank: documentRank,
          departmentId: doc.department_id?.toString() ?? null,
          ownerId: doc.owner_id.toString(),
          category: categoryCode,
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

      const forbidDownload = obligations.some((o) => o.type === 'FORBID_DOWNLOAD');
      const maxMinutesList = obligations
        .filter(
          (o): o is Extract<(typeof obligations)[number], { type: 'MAX_SESSION_MINUTES' }> =>
            o.type === 'MAX_SESSION_MINUTES' && typeof o.minutes === 'number',
        )
        .map((o) => o.minutes);
      const minMinutes = maxMinutesList.length > 0 ? Math.min(...maxMinutesList) : null;
      const anchorMs = validStartedAtMs ?? now.getTime();

      livePolicy = {
        grantedAction: evalAction,
        forbidDownload,
        expiresAtMs: minMinutes !== null ? anchorMs + minMinutes * 60_000 : null,
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

    policy = {
      grantedAction:
        persistedPolicy?.grantedAction ?? livePolicy?.grantedAction ?? ('VIEW' as const),
      forbidDownload: Boolean(persistedPolicy?.forbidDownload || livePolicy?.forbidDownload),
      expiresAtMs: expiryCandidates.length > 0 ? Math.min(...expiryCandidates) : null,
    };

    if (sessionPolicies.size >= 10_000) {
      const oldestKey = sessionPolicies.keys().next().value;
      if (oldestKey) sessionPolicies.delete(oldestKey);
    }
    sessionPolicies.set(session.id, policy);
  }

  if (policy.expiresAtMs !== null && now.getTime() > policy.expiresAtMs) {
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
