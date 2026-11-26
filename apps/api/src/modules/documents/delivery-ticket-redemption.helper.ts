/**
 * Module: Single-Use Download Ticket Atomic Consumption & Real-Time DB Re-Verification Helper
 * Thuật toán: Tiêu Thụ Vé Tải Nguyên Tử & Tái Kiểm Định Trực Tiếp Phiên Xác Thực, Vai Trò RBAC, SoD, Độ Mật & IP/UA Khi Đổi Vé (`BUG-058`).
 *   1. Tiêu thụ một lần băm SHA-256 của vé qua `DistributedStateService.consumeOnce` (`failClosedInProd: true`).
 *   2. Tại thời điểm đổi vé (`/download-with-ticket/:ticket`), kiểm tra trực tiếp `auth_sessions` (`ACTIVE`, chưa hết hạn tuyệt đối/idle),
 *      `users` (`ACTIVE`, không `locked_until`), nạp mới tập vai trò & quyền RBAC thực tế (`DOCUMENT:DOWNLOAD`, không vướng vai trò cấm SoD),
 *      kiểm tra `checkUserClearance`, đối chiếu IP & User-Agent một chiều fail-closed, rồi trả `livePrincipal` mới nhất cho `downloadDocument`.
 */
import { ForbiddenException } from '@nestjs/common';
import crypto from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { isPrivilegedSeparationRoleOrCapability } from '../rbac/permission-matrix.js';
import { normalizeDeliveryClientIp, type DownloadTicketEntry } from './delivery-ticket.helper.js';
import { checkUserClearance } from './pep-clearance.helper.js';
import {
  hasPrivilegedNonBusinessCapability,
  isRestrictedNonBusinessRole,
} from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DOWNLOAD_TICKET_NAMESPACE = 'download-ticket';
const DEFAULT_IDLE_TTL_SECONDS = 28_800;

interface StoredDownloadTicketPayload {
  documentId: string;
  sessionId: string;
  userId: string;
  principal: Record<string, unknown> & { userId: string; departmentId?: string | null };
  issuedIp: string | null;
  issuedUa?: string | null;
  createdAt: number;
  expiresAt: number;
}

/**
 * Thuật toán: Đọc-và-Xóa nguyên tử vé tải dùng một lần trên kho phân tán và khôi phục kiểu `BigInt` cho `AuthPrincipal`.
 */
export async function consumeSingleUseDownloadTicket(
  stateStore: DistributedStateService,
  ticket: string,
): Promise<DownloadTicketEntry> {
  const ticketHash = crypto.createHash('sha256').update(ticket, 'utf8').digest('hex');
  const stored = await stateStore.consumeOnce<StoredDownloadTicketPayload>(
    DOWNLOAD_TICKET_NAMESPACE,
    ticketHash,
    { failClosedInProd: true },
  );

  if (!stored) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_INVALID,
      message: 'Download ticket is invalid or has already been used.',
    });
  }

  if (Date.now() > stored.expiresAt) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_EXPIRED,
      message: 'Download ticket has expired.',
    });
  }

  const restoredPrincipal = {
    ...stored.principal,
    userId: BigInt(stored.principal.userId),
    ...(stored.principal.departmentId !== undefined
      ? {
          departmentId:
            stored.principal.departmentId !== null
              ? BigInt(stored.principal.departmentId)
              : undefined,
        }
      : {}),
  } as unknown as AuthPrincipal;

  return {
    documentId: stored.documentId,
    sessionId: stored.sessionId,
    userId: BigInt(stored.userId),
    principal: restoredPrincipal,
    issuedIp: stored.issuedIp ?? null,
    issuedUa: stored.issuedUa ?? null,
    createdAt: stored.createdAt,
    expiresAt: stored.expiresAt,
  };
}

/**
 * Thuật toán: Tái Kiểm Định Trực Tiếp CSDL & RBAC Thực Tế Tại Thời Điểm Đổi Vé (`reverifyRedeemedTicketState` - `BUG-058`)
 */
export async function reverifyRedeemedTicketState(params: {
  database: PrismaClient;
  grantsService: AccessGrantsService;
  authorization?: AuthorizationService | undefined;
  config?: AppConfigService | undefined;
  entry: DownloadTicketEntry;
  context: RequestContext;
  now: Date;
}): Promise<AuthPrincipal> {
  const { database, grantsService, authorization, config, entry, context, now } = params;

  let liveMfaVerified = Boolean(entry.principal.mfa);
  if (entry.principal.sessionId && typeof database?.authSession?.findFirst === 'function') {
    const rawIdle =
      typeof config?.get === 'function' ? config.get('AUTH_SESSION_IDLE_TTL_SECONDS') : undefined;
    const idleTtlSeconds =
      typeof rawIdle === 'number' && Number.isFinite(rawIdle) && rawIdle > 0
        ? rawIdle
        : DEFAULT_IDLE_TTL_SECONDS;
    const idleCutoff = new Date(now.getTime() - idleTtlSeconds * 1_000);

    const authSession = await database.authSession.findFirst({
      where: {
        id: entry.principal.sessionId,
        user_id: entry.userId,
        status: 'ACTIVE',
        expires_at: { gt: now },
        last_seen_at: { gt: idleCutoff },
      },
    });
    const sessionRow = authSession as {
      status?: string | null;
      expires_at?: Date | string | null;
      last_seen_at?: Date | string | null;
      mfa_verified_at?: Date | null;
    } | null;
    const authSessionActive =
      Boolean(sessionRow) &&
      (!('status' in (sessionRow ?? {})) || sessionRow?.status === 'ACTIVE') &&
      (!sessionRow?.expires_at || new Date(sessionRow.expires_at) > now) &&
      (!sessionRow?.last_seen_at || new Date(sessionRow.last_seen_at) > idleCutoff);
    if (!authSessionActive || !authSession) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: 'Authentication session associated with download ticket is no longer active.',
      });
    }
    if ('mfa_verified_at' in authSession) {
      liveMfaVerified = Boolean((authSession as { mfa_verified_at?: Date | null }).mfa_verified_at);
    }
  }

  let docDepartmentId: bigint | null = null;
  let docRank: number | null = null;

  if (typeof database?.accessSession?.findUnique === 'function') {
    const session = await database.accessSession.findUnique({
      where: { id: entry.sessionId },
    });
    if (!session || session.status !== 'ACTIVE' || session.user_id !== entry.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: 'Access session associated with download ticket is no longer active.',
      });
    }

    const callerIp = normalizeDeliveryClientIp(context?.ip);
    const sessionIp = normalizeDeliveryClientIp(
      (session as { ip_address?: string | null }).ip_address,
    );
    const expectedIp = sessionIp ?? entry.issuedIp;
    if (expectedIp && (!callerIp || callerIp !== expectedIp)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Client IP does not match the access session bound to this download ticket.',
      });
    }

    const callerUa = context?.userAgent?.trim() || null;
    const sessionUa = (session as { user_agent?: string | null }).user_agent?.trim() || null;
    const expectedUa = sessionUa ?? (entry.issuedUa?.trim() || null);
    if (expectedUa && (!callerUa || callerUa !== expectedUa)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message:
          'Client User-Agent does not match the access session bound to this download ticket.',
      });
    }

    if (typeof grantsService?.assertGrantValidForAccess === 'function') {
      await grantsService.assertGrantValidForAccess(
        session.access_grant_id,
        entry.userId,
        'DOWNLOAD',
        now,
        entry.documentId,
      );
    }

    if (session.access_grant_id && typeof database?.accessGrant?.findUnique === 'function') {
      const grant = await database.accessGrant.findUnique({
        where: { id: session.access_grant_id },
      });
      const validFromOk = !grant?.valid_from || new Date(grant.valid_from) <= now;
      const validUntilOk = !grant?.valid_until || new Date(grant.valid_until) > now;
      if (!grant || grant.status !== 'ACTIVE' || !validFromOk || !validUntilOk) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'Underlying access grant is no longer active or has expired.',
        });
      }
    }
  } else {
    const callerIp = normalizeDeliveryClientIp(context?.ip);
    if (entry.issuedIp && (!callerIp || callerIp !== entry.issuedIp)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Client IP does not match the issued download ticket.',
      });
    }
    const callerUa = context?.userAgent?.trim() || null;
    const expectedUa = entry.issuedUa?.trim() || null;
    if (expectedUa && (!callerUa || callerUa !== expectedUa)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Client User-Agent does not match the issued download ticket.',
      });
    }
  }

  let liveUsername = entry.principal.username;
  let liveDepartmentId: bigint | undefined = entry.principal.departmentId;
  if (typeof database?.user?.findUnique === 'function') {
    const user = await database.user.findUnique({
      where: { id: entry.userId },
      select: {
        status: true,
        locked_until: true,
        username: true,
        department_id: true,
      },
    });
    const isLocked =
      user?.locked_until !== null &&
      user?.locked_until !== undefined &&
      new Date(user.locked_until) > now;
    if (!user || user.status !== 'ACTIVE' || isLocked) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'User account associated with download ticket is no longer active or is locked.',
      });
    }
    if (typeof user.username === 'string' && user.username.length > 0) {
      liveUsername = user.username;
    }
    if ('department_id' in user) {
      liveDepartmentId = user.department_id ?? undefined;
    }
  }

  if (typeof database?.document?.findUnique === 'function') {
    const doc = await database.document.findUnique({
      where: { id: entry.documentId },
      include: {
        classification_history: {
          where: { effective_to: null },
          include: { classification_levels: true },
        },
      },
    });
    if (!doc || doc.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Target document is no longer active.',
      });
    }
    docDepartmentId = doc.department_id ?? null;
    docRank = doc.classification_history?.[0]?.classification_levels?.rank ?? 0;
  }

  if (
    docRank !== null &&
    docRank > 0 &&
    typeof database?.userAttributeAssignment?.findFirst === 'function'
  ) {
    const clearanceOk = await checkUserClearance(database, entry.userId, docRank, now);
    if (!clearanceOk) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
        message: 'Caller security clearance is no longer sufficient for this document.',
      });
    }
  }

  let liveRoles: string[] = [...(entry.principal.roles ?? [])];
  let liveRestricted = Boolean(entry.principal.restrictedNonBusiness);

  if (authorization && typeof authorization.effectiveGrants === 'function') {
    const effectiveGrants = await authorization.effectiveGrants(entry.userId);
    const grantRoleCodes = [...new Set(effectiveGrants.map((g) => g.roleCode))];
    liveRoles = grantRoleCodes;
    liveRestricted = isRestrictedNonBusinessRole(
      liveRoles,
      effectiveGrants.map((g) => ({
        code: g.code,
        resource_type: g.resource,
        action: g.action,
      })),
    );
    const provisionalPrincipal: AuthPrincipal = {
      ...entry.principal,
      username: liveUsername,
      roles: liveRoles,
      mfa: liveMfaVerified,
      restrictedNonBusiness: liveRestricted,
      ...(liveDepartmentId !== undefined ? { departmentId: liveDepartmentId } : {}),
    };
    if (
      liveRestricted ||
      (await hasPrivilegedNonBusinessCapability(database, provisionalPrincipal, now))
    ) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Separation of duties forbids privileged roles from redeeming download tickets.',
      });
    }
    const canDownload =
      typeof authorization.hasPermission === 'function'
        ? await authorization.hasPermission(
            provisionalPrincipal,
            'DOCUMENT',
            'DOWNLOAD',
            docDepartmentId !== null ? { targetDepartmentId: docDepartmentId } : undefined,
          )
        : effectiveGrants.some(
            (g) =>
              g.code === 'DOCUMENT_DOWNLOAD' ||
              (g.resource === 'DOCUMENT' && g.action === 'DOWNLOAD'),
          );
    if (!canDownload) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Caller no longer holds DOCUMENT:DOWNLOAD RBAC permission.',
      });
    }
    return provisionalPrincipal;
  }

  if (typeof database?.userRole?.findMany === 'function') {
    const activeAssignments = await database.userRole.findMany({
      where: {
        user_id: entry.userId,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { is_active: true },
      },
      include: {
        roles: {
          include: {
            role_permissions: {
              include: { permissions: true },
            },
          },
        },
      },
    });
    const resolvedCodes: string[] = [];
    let hasDownloadPermission = false;
    let hasDetailedRolePermissions = false;
    for (const assignment of activeAssignments) {
      const roleObj = (
        assignment as {
          roles?: {
            code?: string;
            role_permissions?: Array<{
              permissions?: { code: string; resource_type?: string; action?: string } | null;
            }>;
          } | null;
        }
      ).roles;
      if (!roleObj?.code) continue;
      resolvedCodes.push(roleObj.code);
      if (Array.isArray(roleObj.role_permissions)) {
        hasDetailedRolePermissions = true;
        const perms = roleObj.role_permissions
          .map((rp) => rp.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p));
        if (isPrivilegedSeparationRoleOrCapability(roleObj.code, perms)) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
            message:
              'Separation of duties forbids privileged roles from redeeming download tickets.',
          });
        }
        if (
          perms.some(
            (p) =>
              p.code === 'DOCUMENT_DOWNLOAD' ||
              (p.resource_type === 'DOCUMENT' && p.action === 'DOWNLOAD'),
          )
        ) {
          hasDownloadPermission = true;
        }
      } else if (isPrivilegedSeparationRoleOrCapability(roleObj.code, [])) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'Separation of duties forbids privileged roles from redeeming download tickets.',
        });
      }
    }
    liveRoles = [...new Set(resolvedCodes)];
    if (resolvedCodes.length === 0 || (hasDetailedRolePermissions && !hasDownloadPermission)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Caller no longer holds DOCUMENT:DOWNLOAD RBAC permission.',
      });
    }
  } else if (isRestrictedNonBusinessRole(entry.principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Separation of duties forbids privileged roles from redeeming download tickets.',
    });
  }

  return {
    ...entry.principal,
    username: liveUsername,
    roles: liveRoles,
    mfa: liveMfaVerified,
    restrictedNonBusiness: false,
    ...(liveDepartmentId !== undefined ? { departmentId: liveDepartmentId } : {}),
  };
}
