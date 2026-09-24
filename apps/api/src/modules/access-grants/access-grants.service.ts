import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateAccessGrantInput,
  type RevokeAccessGrantInput,
  type ListAccessGrantsInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { AuthorizationCache } from '../rbac/authorization-cache.js';
import { AbacService } from '../abac/abac.service.js';
import { AppConfigService } from '../../config/config.service.js';
import { AccessGrantAuditService } from './access-grant-audit.service.js';
import { RedlockService } from '../concurrency/redlock.service.js';

export interface GrantDetail {
  id: string;
  documentId: string;
  principalType: string;
  principalUserId: string | null;
  principalRoleId: string | null;
  source: string;
  accessRequestId: string | null;
  permissions: string[];
  validFrom: string;
  validUntil: string;
  status: string;
  grantedBy: string;
  grantedAt: string;
  revokedBy: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  version: number;
}

export interface GrantListResult {
  data: GrantDetail[];
  page: number;
  pageSize: number;
  hasMore: boolean;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AccessGrantsService {
  private readonly logger = new Logger(AccessGrantsService.name);
  private readonly database: PrismaClient;
  private readonly maxDurationDays: number;

  constructor(
    private readonly audit: AccessGrantAuditService,
    private readonly authorization: AuthorizationService,
    private readonly cache: AuthorizationCache,
    private readonly abac: AbacService,
    private readonly config: AppConfigService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly redlock?: RedlockService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.maxDurationDays = this.config.get('GRANT_MAX_DURATION_DAYS');
  }

  /**
   * Create a time-bound access grant.
   *
   * D-BR14: Owner grants directly to exactly one USER or ROLE, only VIEW/DOWNLOAD,
   * with mandatory valid_from/valid_until. Must pass RBAC, ownership, clearance,
   * classification allow_download, and ABAC before creating.
   */
  async createGrant(
    input: CreateAccessGrantInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<GrantDetail> {
    const now = new Date();
    const validFrom = new Date(input.validFrom);
    const validUntil = new Date(input.validUntil);

    // Validate time range
    if (validUntil <= validFrom) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
        message: 'validUntil must be after validFrom.',
      });
    }

    // Check max duration
    const durationMs = validUntil.getTime() - validFrom.getTime();
    const maxMs = this.maxDurationDays * 24 * 60 * 60 * 1000;
    if (durationMs > maxMs) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
        message: `Grant duration cannot exceed ${this.maxDurationDays} days.`,
      });
    }

    // 1. Load document and verify status
    const document = await this.database.document.findUnique({
      where: { id: input.documentId },
      include: {
        classification_history: {
          where: { effective_to: null },
          include: { classification_levels: true },
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

    // 2. Assert caller is document owner or has ACCESS_GRANT/CREATE permission
    const isOwner = document.owner_id === principal.userId;
    if (!isOwner) {
      const hasPermission = await this.authorization.hasPermission(
        principal,
        'ACCESS_GRANT',
        'CREATE',
        { targetDepartmentId: document.department_id },
      );
      if (!hasPermission) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message: 'Only the document owner or authorized administrator can grant access.',
        });
      }
    }

    // 3. Validate principal target
    if (input.principalType === 'USER') {
      if (!input.principalUserId) {
        throw new BadRequestException({
          errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
          message: 'principalUserId is required when principalType is USER.',
        });
      }
      const targetUser = await this.database.user.findUnique({
        where: { id: input.principalUserId },
        select: { id: true, status: true },
      });
      if (!targetUser) {
        throw new NotFoundException({
          errorCode: AppErrorCode.USER_NOT_ACTIVE,
          message: 'Target user was not found.',
        });
      }
      if (targetUser.status !== 'ACTIVE') {
        throw new BadRequestException({
          errorCode: AppErrorCode.USER_NOT_ACTIVE,
          message: 'Target user account is not active.',
        });
      }
    } else if (input.principalType === 'ROLE') {
      if (!input.principalRoleId) {
        throw new BadRequestException({
          errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
          message: 'principalRoleId is required when principalType is ROLE.',
        });
      }
      const targetRole = await this.database.role.findUnique({
        where: { id: input.principalRoleId },
        select: { id: true, is_active: true },
      });
      if (!targetRole) {
        throw new NotFoundException({
          errorCode: AppErrorCode.ROLE_NOT_ACTIVE,
          message: 'Target role was not found.',
        });
      }
      if (!targetRole.is_active) {
        throw new BadRequestException({
          errorCode: AppErrorCode.ROLE_NOT_ACTIVE,
          message: 'Target role is not active.',
        });
      }
    }

    // 4. Check clearance for USER grants (D-BR04)
    const currentClassification = document.classification_history[0];
    const documentRank = currentClassification?.classification_levels?.rank ?? 0;

    if (input.principalType === 'USER' && input.principalUserId) {
      const clearanceAssignment = await this.database.userAttributeAssignment.findFirst({
        where: {
          user_id: input.principalUserId,
          attribute_definitions: { code: 'CLEARANCE_LEVEL' },
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        },
        include: { attribute_options: true },
        orderBy: { attribute_options: { numeric_rank: 'desc' } },
      });

      const userRank = clearanceAssignment?.attribute_options?.numeric_rank ?? 0;
      if (userRank < documentRank) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.GRANT_CLEARANCE_INSUFFICIENT,
          message: 'User clearance level is insufficient for this document classification.',
        });
      }
    }

    // 5. Check classification allow_download if DOWNLOAD permission requested
    if (input.permissions.includes('DOWNLOAD')) {
      if (currentClassification && !currentClassification.classification_levels.allow_download) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
          message: 'Document classification does not allow download.',
        });
      }
    }

    // 6. Run ABAC evaluation for grant creation
    // Security hardening: For USER grants, evaluate target recipient attributes.
    // For ROLE grants, evaluate caller attributes at grant creation; individual user
    // ABAC + clearance will be strictly enforced at every access attempt (assertGrantValidForAccess).
    const subjectUserId =
      input.principalType === 'USER' && input.principalUserId
        ? input.principalUserId
        : principal.userId;
    const subjectAttributes = await this.buildSubjectAttributes(subjectUserId);
    const resourceAttributes = this.buildResourceAttributes(document, currentClassification);

    for (const permission of input.permissions) {
      const abacResult = await this.abac.evaluate({
        resourceType: 'DOCUMENT',
        action: permission as 'VIEW' | 'DOWNLOAD',
        subject: subjectAttributes,
        resource: resourceAttributes,
        environment: {
          currentTime: now.toISOString(),
          ip: context.ip,
          trustedNetwork: false,
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

    // 7. Overlap detection and create/extend within transaction
    const grantId = randomUUID();
    let resultGrant: GrantDetail;
    let wasExtended = false;

    const executeGrantTx = async () => {
      await this.database.$transaction(
        async (tx) => {
          // Lock the document row for grant manipulation
          await tx.$executeRawUnsafe(
            'SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE',
            input.documentId,
          );

          // Check for existing ACTIVE grant with same document + principal
          const existingGrant = await tx.accessGrant.findFirst({
            where: {
              document_id: input.documentId,
              principal_type: input.principalType,
              principal_user_id:
                input.principalType === 'USER' ? (input.principalUserId ?? null) : null,
              principal_role_id:
                input.principalType === 'ROLE' ? (input.principalRoleId ?? null) : null,
              status: 'ACTIVE',
            },
            include: {
              access_grant_permissions: true,
            },
          });

          if (existingGrant) {
            const existingPerms = existingGrant.access_grant_permissions.map((p) => p.permission);
            const requestedPerms = [...new Set(input.permissions)].sort();
            const samePerms = existingPerms.sort().join(',') === requestedPerms.join(',');

            if (samePerms) {
              // Same permissions → extend the existing grant's valid_until
              const newValidUntil =
                validUntil > existingGrant.valid_until ? validUntil : existingGrant.valid_until;
              const newValidFrom =
                validFrom < existingGrant.valid_from ? validFrom : existingGrant.valid_from;

              // Security hardening: extended grant cannot exceed maxDurationDays from now
              const extensionDurationMs = newValidUntil.getTime() - now.getTime();
              if (extensionDurationMs > maxMs) {
                throw new BadRequestException({
                  errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
                  message: `Extended grant duration cannot exceed ${this.maxDurationDays} days from now.`,
                });
              }

              await tx.accessGrant.update({
                where: { id: existingGrant.id },
                data: {
                  valid_from: newValidFrom,
                  valid_until: newValidUntil,
                  version: { increment: 1 },
                },
              });

              wasExtended = true;

              await this.audit.record(
                {
                  action: 'GRANT_EXTENDED',
                  outcome: 'SUCCESS',
                  objectId: existingGrant.id,
                  documentId: input.documentId,
                  details: {
                    principalType: input.principalType,
                    principalId:
                      (input.principalUserId ?? input.principalRoleId)?.toString() ?? null,
                    previousValidUntil: existingGrant.valid_until.toISOString(),
                    newValidUntil: newValidUntil.toISOString(),
                    previousValidFrom: existingGrant.valid_from.toISOString(),
                    newValidFrom: newValidFrom.toISOString(),
                  },
                },
                principal,
                context,
                tx,
              );

              if (input.accessRequestId) {
                await tx.accessRequest.update({
                  where: { id: input.accessRequestId },
                  data: { status: 'APPROVED', updated_at: now },
                });
                await tx.accessRequestDecision.create({
                  data: {
                    access_request_id: input.accessRequestId,
                    decision: 'APPROVED',
                    decided_by: principal.userId,
                    approved_from: newValidFrom,
                    approved_until: newValidUntil,
                    decided_at: now,
                  },
                });
              }

              const updated = await tx.accessGrant.findUnique({
                where: { id: existingGrant.id },
                include: { access_grant_permissions: true },
              });
              resultGrant = this.toGrantDetail(updated!);
            } else {
              // Different permissions overlap → reject
              throw new ConflictException({
                errorCode: AppErrorCode.GRANT_OVERLAP_EXISTS,
                message:
                  'An active grant with different permissions already exists for this document and principal. Revoke the existing grant first.',
              });
            }
          } else {
            // No overlap: create new grant
            const created = await tx.accessGrant.create({
              data: {
                id: grantId,
                document_id: input.documentId,
                principal_type: input.principalType,
                principal_user_id: input.principalUserId ?? null,
                principal_role_id: input.principalRoleId ?? null,
                source: input.accessRequestId ? 'ACCESS_REQUEST' : 'DIRECT',
                access_request_id: input.accessRequestId ?? null,
                valid_from: validFrom,
                valid_until: validUntil,
                status: 'ACTIVE',
                granted_by: principal.userId,
                granted_at: now,
                version: 0,
                access_grant_permissions: {
                  createMany: {
                    data: [...new Set(input.permissions)].map((p) => ({
                      permission: p,
                    })),
                  },
                },
              },
              include: { access_grant_permissions: true },
            });

            await this.audit.record(
              {
                action: 'GRANT_CREATED',
                outcome: 'SUCCESS',
                objectId: grantId,
                documentId: input.documentId,
                details: {
                  principalType: input.principalType,
                  principalId: (input.principalUserId ?? input.principalRoleId)?.toString() ?? null,
                  permissions: input.permissions.join(','),
                  validFrom: validFrom.toISOString(),
                  validUntil: validUntil.toISOString(),
                  source: input.accessRequestId ? 'ACCESS_REQUEST' : 'DIRECT',
                  accessRequestId: input.accessRequestId ?? null,
                },
              },
              principal,
              context,
              tx,
            );

            if (input.accessRequestId) {
              await tx.accessRequest.update({
                where: { id: input.accessRequestId },
                data: { status: 'APPROVED', updated_at: now },
              });
              await tx.accessRequestDecision.create({
                data: {
                  access_request_id: input.accessRequestId,
                  decision: 'APPROVED',
                  decided_by: principal.userId,
                  approved_from: validFrom,
                  approved_until: validUntil,
                  decided_at: now,
                },
              });
            }

            resultGrant = this.toGrantDetail(created);
          }
        },
        { isolationLevel: 'Serializable' },
      );

      // Fire notification async (D-BR20: don't rollback grant on notification failure)
      this.fireNotificationAsync(
        wasExtended ? 'GRANT_EXTENDED' : 'GRANT_CREATED',
        input,
        principal,
      ).catch((err: unknown) => {
        this.logger.warn(
          `Notification for grant ${wasExtended ? 'extension' : 'creation'} failed: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      });
    };

    const principalId =
      input.principalType === 'USER' ? input.principalUserId : input.principalRoleId;
    const lockResource = `access-grant:${input.documentId}:${input.principalType}:${principalId}`;

    if (this.redlock) {
      await this.redlock.withLock(lockResource, 5000, executeGrantTx);
    } else {
      await executeGrantTx();
    }

    return resultGrant!;
  }

  /**
   * Revoke a grant immediately with reason, terminate active sessions,
   * and invalidate caches.
   *
   * D-BR15: Thu hồi có reason, giữ lịch sử, terminate session và vô hiệu cache.
   * D-BR20: Notification retry independently, no rollback on failure.
   */
  async revokeGrant(
    grantId: string,
    input: RevokeAccessGrantInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<GrantDetail> {
    const start = performance.now();
    const now = new Date();

    // Load grant with optimistic locking
    const grant = await this.database.accessGrant.findUnique({
      where: { id: grantId },
      include: {
        access_grant_permissions: true,
        documents: { select: { owner_id: true, department_id: true } },
      },
    });

    if (!grant) {
      throw new NotFoundException({
        errorCode: AppErrorCode.GRANT_NOT_FOUND,
        message: 'Access grant was not found.',
      });
    }

    // Idempotency: if already REVOKED, return existing without error
    if (grant.status === 'REVOKED') {
      return this.toGrantDetail(grant);
    }

    // Only ACTIVE or SUSPENDED grants can be revoked
    if (grant.status !== 'ACTIVE' && grant.status !== 'SUSPENDED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_ALREADY_REVOKED,
        message: `Cannot revoke a grant with status ${grant.status}.`,
      });
    }

    // Assert caller is document owner or has ACCESS_GRANT/REVOKE permission
    const isOwner = grant.documents.owner_id === principal.userId;
    if (!isOwner) {
      const hasPermission = await this.authorization.hasPermission(
        principal,
        'ACCESS_GRANT',
        'REVOKE',
        { targetDepartmentId: grant.documents.department_id },
      );
      if (!hasPermission) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message: 'Only the document owner or authorized administrator can revoke grants.',
        });
      }
    }

    // Optimistic concurrency check
    if (input.expectedVersion !== undefined && input.expectedVersion !== grant.version) {
      throw new ConflictException({
        errorCode: AppErrorCode.GRANT_CONCURRENCY_CONFLICT,
        message: 'Grant was modified by another request. Please retry.',
      });
    }

    let terminatedSessionCount = 0;
    const affectedUserIds = new Set<bigint>();

    await this.database.$transaction(
      async (tx) => {
        // Lock the grant row
        await tx.$executeRawUnsafe(
          'SELECT id FROM access_grants WHERE id = $1::uuid FOR UPDATE',
          grantId,
        );

        // Re-check status after lock (concurrent revoke protection)
        const locked = await tx.accessGrant.findUnique({
          where: { id: grantId },
          select: { status: true, version: true },
        });

        if (!locked || locked.status === 'REVOKED') {
          // Already revoked by concurrent request — idempotent
          return;
        }

        if (locked.status !== 'ACTIVE' && locked.status !== 'SUSPENDED') {
          throw new BadRequestException({
            errorCode: AppErrorCode.GRANT_ALREADY_REVOKED,
            message: `Cannot revoke a grant with status ${locked.status}.`,
          });
        }

        // Update grant status to REVOKED
        await tx.accessGrant.update({
          where: { id: grantId },
          data: {
            status: 'REVOKED',
            revoked_by: principal.userId,
            revoked_at: now,
            revoke_reason: input.reason,
            version: { increment: 1 },
          },
        });

        // Terminate all ACTIVE sessions associated with this grant
        const activeSessions = await tx.accessSession.findMany({
          where: {
            access_grant_id: grantId,
            status: 'ACTIVE',
          },
          select: { id: true, user_id: true },
        });

        for (const session of activeSessions) {
          affectedUserIds.add(session.user_id);
        }

        if (activeSessions.length > 0) {
          const result = await tx.accessSession.updateMany({
            where: {
              access_grant_id: grantId,
              status: 'ACTIVE',
            },
            data: {
              status: 'TERMINATED',
              ended_at: now,
              terminated_reason: `Grant revoked: ${input.reason}`,
            },
          });
          terminatedSessionCount = result.count;
        }

        // Record audit within transaction
        await this.audit.record(
          {
            action: 'GRANT_REVOKED',
            outcome: 'SUCCESS',
            objectId: grantId,
            documentId: grant.document_id,
            details: {
              reason: input.reason,
              terminatedSessions: terminatedSessionCount,
              principalType: grant.principal_type,
              principalUserId: grant.principal_user_id?.toString() ?? null,
              principalRoleId: grant.principal_role_id?.toString() ?? null,
            },
          },
          principal,
          context,
          tx,
        );
      },
      { isolationLevel: 'Serializable' },
    );

    // Invalidate authorization cache for all affected users
    for (const userId of affectedUserIds) {
      this.cache.invalidateUser(userId);
    }

    // Also invalidate the grant principal's cache
    if (grant.principal_user_id) {
      this.cache.invalidateUser(grant.principal_user_id);
    }

    // Fire notification async — independent, no rollback on failure (D-BR20)
    this.fireRevokeNotificationAsync(grant, input.reason, principal).catch((err: unknown) => {
      this.logger.warn(
        `Revocation notification failed for grant ${grantId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    });

    // Return updated grant
    const updated = await this.database.accessGrant.findUnique({
      where: { id: grantId },
      include: { access_grant_permissions: true },
    });

    const durationSeconds = (performance.now() - start) / 1000;
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordGrantRevocation(durationSeconds, true);
    } catch {
      // Fallback
    }

    return this.toGrantDetail(updated!);
  }

  /**
   * Get a single grant by ID. Caller must have visibility.
   */
  async getGrant(grantId: string, principal: AuthPrincipal): Promise<GrantDetail> {
    const grant = await this.database.accessGrant.findUnique({
      where: { id: grantId },
      include: {
        access_grant_permissions: true,
        documents: { select: { owner_id: true, department_id: true } },
      },
    });

    if (!grant) {
      throw new NotFoundException({
        errorCode: AppErrorCode.GRANT_NOT_FOUND,
        message: 'Access grant was not found.',
      });
    }

    // Visibility: owner, grant principal, or has ACCESS_GRANT/VIEW permission
    const isOwner = grant.documents.owner_id === principal.userId;
    const isPrincipal = grant.principal_user_id === principal.userId;
    if (!isOwner && !isPrincipal) {
      const hasPermission = await this.authorization.hasPermission(
        principal,
        'ACCESS_GRANT',
        'VIEW',
        { targetDepartmentId: grant.documents.department_id },
      );
      if (!hasPermission) {
        throw new NotFoundException({
          errorCode: AppErrorCode.GRANT_NOT_FOUND,
          message: 'Access grant was not found.',
        });
      }
    }

    return this.toGrantDetail(grant);
  }

  /**
   * List grants with pagination and filters.
   * Scoped to caller's visible documents.
   */
  async listGrants(
    input: ListAccessGrantsInput,
    principal: AuthPrincipal,
  ): Promise<GrantListResult> {
    const where: Record<string, unknown> = {};

    // Filter by document if specified, checking ownership/permission
    if (input.documentId) {
      const doc = await this.database.document.findUnique({
        where: { id: input.documentId },
        select: { owner_id: true, department_id: true },
      });
      if (!doc) {
        return { data: [], page: input.page, pageSize: input.pageSize, hasMore: false };
      }
      const isOwner = doc.owner_id === principal.userId;
      if (!isOwner) {
        const hasPermission = await this.authorization.hasPermission(
          principal,
          'ACCESS_GRANT',
          'VIEW',
          { targetDepartmentId: doc.department_id },
        );
        if (!hasPermission) {
          return { data: [], page: input.page, pageSize: input.pageSize, hasMore: false };
        }
      }
      where['document_id'] = input.documentId;
    } else {
      // Without document filter: show grants for owned documents or grants to self
      where['OR'] = [
        { documents: { owner_id: principal.userId } },
        { principal_user_id: principal.userId },
      ];
    }

    if (input.status) {
      where['status'] = input.status;
    }
    if (input.principalType) {
      where['principal_type'] = input.principalType;
    }

    const sortField =
      input.sort === 'granted_at'
        ? 'granted_at'
        : input.sort === 'valid_until'
          ? 'valid_until'
          : 'status';

    const skip = (input.page - 1) * input.pageSize;

    const grants = await this.database.accessGrant.findMany({
      where,
      include: { access_grant_permissions: true },
      orderBy: [{ [sortField]: input.order }, { id: 'asc' }],
      skip,
      take: input.pageSize + 1,
    });

    const hasMore = grants.length > input.pageSize;
    const data = grants.slice(0, input.pageSize).map((g) => this.toGrantDetail(g));

    return { data, page: input.page, pageSize: input.pageSize, hasMore };
  }

  /**
   * Check if a grant is valid for access at the current moment.
   * Used by access session creation (Prompt 13) and access checks.
   *
   * D-BR04: Grant cho role vẫn kiểm tra clearance từng user tại mỗi lần truy cập.
   * D-BR14: VIEW không suy ra DOWNLOAD.
   * D-BR15: Kiểm tra thời gian mỗi lần, không phụ thuộc worker.
   */
  async assertGrantValidForAccess(
    grantId: string,
    userId: bigint,
    requestedAction: 'VIEW' | 'DOWNLOAD',
    now: Date = new Date(),
  ): Promise<{
    grant: { id: string; document_id: string; principal_type: string };
    documentRank: number;
  }> {
    const grant = await this.database.accessGrant.findUnique({
      where: { id: grantId },
      include: {
        access_grant_permissions: true,
        documents: {
          include: {
            classification_history: {
              where: { effective_to: null },
              include: { classification_levels: true },
            },
          },
        },
      },
    });

    if (!grant) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_NOT_FOUND,
        message: 'Access grant was not found.',
      });
    }

    // Check document status: cannot access non-active or archived document
    if (grant.documents.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Document is not in active state.',
      });
    }

    // Check grant status
    if (grant.status === 'REVOKED') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_REVOKED,
        message: 'Access grant has been revoked.',
      });
    }

    if (grant.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_EXPIRED,
        message: `Access grant status is ${grant.status}.`,
      });
    }

    // Check time validity: half-open interval [valid_from, valid_until)
    if (now < grant.valid_from) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_EXPIRED,
        message: 'Access grant is not yet valid.',
      });
    }

    if (now >= grant.valid_until) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_EXPIRED,
        message: 'Access grant has expired.',
      });
    }

    // Check user is still ACTIVE
    const user = await this.database.user.findUnique({
      where: { id: userId },
      select: { status: true },
    });

    if (!user || user.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.USER_NOT_ACTIVE,
        message: 'User account is not active.',
      });
    }

    // Check permission: VIEW does NOT imply DOWNLOAD
    const grantedPerms = grant.access_grant_permissions.map((p) => p.permission);
    if (!grantedPerms.includes(requestedAction)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: `Grant does not include ${requestedAction} permission.`,
      });
    }

    // Check clearance (D-BR04: even for ROLE grants, check individual user clearance)
    const currentClassification = grant.documents.classification_history[0];
    const documentRank = currentClassification?.classification_levels?.rank ?? 0;

    const clearanceAssignment = await this.database.userAttributeAssignment.findFirst({
      where: {
        user_id: userId,
        attribute_definitions: { code: 'CLEARANCE_LEVEL' },
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
      include: { attribute_options: true },
      orderBy: { attribute_options: { numeric_rank: 'desc' } },
    });

    const userRank = clearanceAssignment?.attribute_options?.numeric_rank ?? 0;
    if (userRank < documentRank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.CLEARANCE_INSUFFICIENT,
        message: 'User clearance level is insufficient for this document.',
      });
    }

    // For ROLE grants: verify user actually holds the role currently
    if (grant.principal_type === 'ROLE' && grant.principal_role_id) {
      const hasRole = await this.database.userRole.findFirst({
        where: {
          user_id: userId,
          role_id: grant.principal_role_id,
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
      });

      if (!hasRole) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'User does not currently hold the required role for this grant.',
        });
      }
    }

    // For USER grants: verify caller is the actual recipient (IDOR protection)
    if (grant.principal_type === 'USER' && grant.principal_user_id !== userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Grant was not issued to this user.',
      });
    }

    // Check classification allow_download if DOWNLOAD requested
    if (
      requestedAction === 'DOWNLOAD' &&
      currentClassification &&
      !currentClassification.classification_levels.allow_download
    ) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        message: 'Document classification does not allow download.',
      });
    }

    return {
      grant: {
        id: grant.id,
        document_id: grant.document_id,
        principal_type: grant.principal_type,
      },
      documentRank,
    };
  }

  /**
   * Batch expire grants past valid_until. Called by worker.
   * Returns count of expired grants.
   */
  async expireGrantsBatch(batchSize: number = 100): Promise<number> {
    const now = new Date();
    let expiredCount = 0;

    await this.database.$transaction(
      async (tx) => {
        // Select grants to expire with row locking
        const expiring = await tx.$queryRawUnsafe<Array<{ id: string }>>(
          `SELECT id FROM access_grants WHERE status = 'ACTIVE' AND valid_until <= $1 LIMIT $2 FOR UPDATE SKIP LOCKED`,
          now,
          batchSize,
        );

        if (expiring.length === 0) return;

        const ids = expiring.map((r) => r.id);

        // Update grants to EXPIRED
        const result = await tx.accessGrant.updateMany({
          where: { id: { in: ids } },
          data: { status: 'EXPIRED' },
        });
        expiredCount = result.count;

        // Terminate related active sessions
        const sessions = await tx.accessSession.findMany({
          where: {
            access_grant_id: { in: ids },
            status: 'ACTIVE',
          },
          select: { user_id: true },
        });

        if (sessions.length > 0) {
          await tx.accessSession.updateMany({
            where: {
              access_grant_id: { in: ids },
              status: 'ACTIVE',
            },
            data: {
              status: 'TERMINATED',
              ended_at: now,
              terminated_reason: 'Grant expired',
            },
          });

          // Collect unique user IDs for cache invalidation
          const userIds = new Set(sessions.map((s) => s.user_id));
          for (const userId of userIds) {
            this.cache.invalidateUser(userId);
          }
        }
      },
      { isolationLevel: 'Serializable' },
    );

    return expiredCount;
  }

  // --- Private helpers ---

  private toGrantDetail(grant: {
    id: string;
    document_id: string;
    principal_type: string;
    principal_user_id: bigint | null;
    principal_role_id: bigint | null;
    source: string;
    access_request_id: string | null;
    valid_from: Date;
    valid_until: Date;
    status: string;
    granted_by: bigint;
    granted_at: Date;
    revoked_by: bigint | null;
    revoked_at: Date | null;
    revoke_reason: string | null;
    version: number;
    access_grant_permissions: Array<{ permission: string }>;
  }): GrantDetail {
    return {
      id: grant.id,
      documentId: grant.document_id,
      principalType: grant.principal_type,
      principalUserId: grant.principal_user_id?.toString() ?? null,
      principalRoleId: grant.principal_role_id?.toString() ?? null,
      source: grant.source,
      accessRequestId: grant.access_request_id,
      permissions: grant.access_grant_permissions.map((p) => p.permission),
      validFrom: grant.valid_from.toISOString(),
      validUntil: grant.valid_until.toISOString(),
      status: grant.status,
      grantedBy: grant.granted_by.toString(),
      grantedAt: grant.granted_at.toISOString(),
      revokedBy: grant.revoked_by?.toString() ?? null,
      revokedAt: grant.revoked_at?.toISOString() ?? null,
      revokeReason: grant.revoke_reason,
      version: grant.version,
    };
  }

  private async buildSubjectAttributes(userId: bigint): Promise<{
    clearanceRank: number | null;
    departmentId: string | null;
    employmentStatus: string | null;
    projects: string[];
  }> {
    const now = new Date();
    const user = await this.database.user.findUnique({
      where: { id: userId },
      select: { department_id: true, status: true },
    });

    const clearance = await this.database.userAttributeAssignment.findFirst({
      where: {
        user_id: userId,
        attribute_definitions: { code: 'CLEARANCE_LEVEL' },
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
      include: { attribute_options: true },
      orderBy: { attribute_options: { numeric_rank: 'desc' } },
    });

    return {
      clearanceRank: clearance?.attribute_options?.numeric_rank ?? null,
      departmentId: user?.department_id?.toString() ?? null,
      employmentStatus: user?.status ?? null,
      projects: [],
    };
  }

  private buildResourceAttributes(
    document: {
      owner_id: bigint;
      department_id: bigint;
      status: string;
    },
    classification:
      | {
          classification_levels: { rank: number };
          business_categories?: { code: string };
        }
      | null
      | undefined,
  ): {
    classificationRank: number | null;
    ownerId: string | null;
    departmentId: string | null;
    category: string | null;
    status: string | null;
  } {
    return {
      classificationRank: classification?.classification_levels?.rank ?? null,
      ownerId: document.owner_id.toString(),
      departmentId: document.department_id.toString(),
      category:
        (classification as { business_categories?: { code: string } } | undefined)
          ?.business_categories?.code ?? null,
      status: document.status,
    };
  }

  private async fireNotificationAsync(
    _type: string,
    _input: CreateAccessGrantInput,
    _principal: AuthPrincipal,
  ): Promise<void> {
    // Notification dispatch — placeholder for Prompt 15.
    // D-BR20: retry independently, no rollback on failure.
  }

  private async fireRevokeNotificationAsync(
    _grant: {
      document_id: string;
      principal_user_id: bigint | null;
      principal_role_id: bigint | null;
    },
    _reason: string,
    _principal: AuthPrincipal,
  ): Promise<void> {
    // Revocation notification — placeholder for Prompt 15.
    // D-BR20: retry independently, no rollback on failure.
  }
}
