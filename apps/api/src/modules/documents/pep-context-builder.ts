/**
 * Module: PEP Policy Information Point (PIP) Context Builder & Deny Audit Helper
 * Algorithm: Resolves subject ABAC attributes (`CLEARANCE_LEVEL`, `PROJECT`, department, status),
 *   matches caller IP against trusted CIDR blocks, checks SoD role exclusions, and records fail-closed deny audits.
 */
import type { Logger } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { cidrMatch } from '../abac/policy-engine.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { PRIVILEGED_SEPARATION_ROLES } from '../rbac/permission-matrix.js';
import type { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface PepAccessContext {
  action: 'VIEW' | 'DOWNLOAD';
  grantId?: string | undefined;
  deviceFingerprint?: string | undefined;
  now?: Date | undefined;
}

export interface PepEvaluationResult {
  sessionId: string;
  documentId: string;
  documentTitle: string;
  documentCode: string | null;
  // CONFLICT-RESOLVED: Chuyển documentVersionId sang string để tránh lỗi Fastify JSON.stringify BigInt HTTP 500 trên POST /documents/:id/sessions.
  documentVersionId: string;
  versionNo: number;
  grantId: string;
  watermarkRequired: boolean;
  allowDownload: boolean;
  classificationRank: number;
  obligations: string[];
}

export interface ActiveSessionPolicy {
  grantedAction: 'VIEW' | 'DOWNLOAD';
  forbidDownload: boolean;
  expiresAtMs: number | null;
}

/**
 * Algorithm / Thuật toán: Kiểm tra Phân tách nhiệm vụ (SoD) bất biến tại cổng PEP cho `SYSTEM_ADMIN`, `SECURITY_OFFICER` và `AUDITOR`.
 */
export function isRestrictedNonBusinessRole(roles: readonly string[]): boolean {
  // CONFLICT-RESOLVED: Removed `!hasBusinessRole` bypass and included `SECURITY_OFFICER` via `PRIVILEGED_SEPARATION_ROLES`.
  return roles.some((role) => PRIVILEGED_SEPARATION_ROLES.has(role));
}

/**
 * Algorithm: Trusted Network CIDR Membership Evaluation
 * Splits comma-delimited `ABAC_TRUSTED_NETWORK_CIDRS` and checks IP membership via `cidrMatch`.
 */
export function resolvePepTrustedNetwork(
  config: AppConfigService | undefined,
  ip: string,
): boolean {
  const rawTrustedCidrs =
    typeof config?.get === 'function' ? config.get('ABAC_TRUSTED_NETWORK_CIDRS') : undefined;
  if (typeof rawTrustedCidrs !== 'string' || rawTrustedCidrs.length === 0) {
    return false;
  }
  return rawTrustedCidrs
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .some((cidr) => cidrMatch(ip, cidr));
}

/**
 * Algorithm: PIP Subject Attribute Hydration
 * Loads user department, employment status, highest active `CLEARANCE_LEVEL` rank (`is_active: true`), and sorted active `PROJECT` codes.
 */
export async function buildPepSubjectAttributes(
  database: PrismaClient,
  userId: bigint,
  now: Date,
): Promise<{
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
}> {
  const user = await database.user?.findUnique?.({
    where: { id: userId },
    select: { department_id: true, status: true },
  });

  const clearance = await database.userAttributeAssignment.findFirst({
    where: {
      user_id: userId,
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
  const activeClearanceRank =
    (clearance as { attribute_definitions?: { is_active?: boolean } } | null)?.attribute_definitions
      ?.is_active === false || clearance?.attribute_options?.is_active === false
      ? null
      : (clearance?.attribute_options?.numeric_rank ?? null);

  let projects: string[] = [];
  if (typeof database?.userAttributeAssignment?.findMany === 'function') {
    const projectAssignments = await database.userAttributeAssignment.findMany({
      where: {
        user_id: userId,
        attribute_definitions: { code: 'PROJECT', is_active: true },
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          // CONFLICT-RESOLVED: Đồng bộ tên cột khóa ngoại option_id của bảng UserAttributeAssignment trong abac.prisma thay cho attribute_option_id không tồn tại.
          { OR: [{ option_id: null }, { attribute_options: { is_active: true } }] },
        ],
      },
      include: { attribute_options: true },
    });
    projects = projectAssignments
      .filter(
        (a) =>
          (a as { attribute_options?: { is_active?: boolean } | null }).attribute_options
            ?.is_active !== false,
      )
      .map(
        (a) =>
          (
            a as {
              attribute_options?: { value_code?: string } | null;
              value_text?: string | null;
            }
          ).attribute_options?.value_code ?? (a as { value_text?: string | null }).value_text,
      )
      .filter((v): v is string => typeof v === 'string' && v.length > 0)
      .sort();
  }

  return {
    clearanceRank: activeClearanceRank,
    departmentId: user?.department_id?.toString() ?? null,
    employmentStatus: user?.status ?? null,
    projects,
  };
}

/**
 * Algorithm: Fail-Closed Access Deny Audit Recorder
 * Emits `ACCESS_DENIED` audit event and rethrows persistence errors in production.
 */
export async function recordPepDenyAudit(params: {
  audit: DocumentDeliveryAuditService;
  logger: Logger;
  documentId: string;
  grantId: string | null;
  reasonCode: string;
  reasonMessage: string;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  try {
    await params.audit.record(
      {
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        documentId: params.documentId,
        objectId: params.grantId,
        reasonCode: params.reasonCode,
        details: { message: params.reasonMessage },
      },
      params.principal,
      params.context,
    );
  } catch (auditErr) {
    params.logger.error(`Failed to record access deny audit: ${auditErr}`);
    if (process.env['NODE_ENV'] === 'production') {
      throw auditErr;
    }
  }
}
