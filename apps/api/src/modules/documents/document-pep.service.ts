import {
  Injectable,
  Logger,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AbacService } from '../abac/abac.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

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
  documentVersionId: bigint;
  versionNo: number;
  grantId: string;
  watermarkRequired: boolean;
  allowDownload: boolean;
  classificationRank: number;
  obligations: string[];
}

@Injectable()
export class DocumentPepService {
  private readonly logger = new Logger(DocumentPepService.name);
  private readonly database: PrismaClient;

  constructor(
    private readonly abac: AbacService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Policy Enforcement Point (PEP) for controlled document access.
   *
   * 1. Evaluates Grant validity, User active state, Clearance, and Classification rules.
   * 2. Evaluates PDP (ABAC) policies.
   * 3. Enforces Obligations (FORBID_DOWNLOAD, REQUIRE_WATERMARK).
   * 4. When PERMIT, atomically creates an AccessSession tied to the grant, user, and current version.
   * 5. Emits tamper-resistant audit log.
   */
  async enforceAccess(
    documentId: string,
    principal: AuthPrincipal,
    context: RequestContext,
    pepContext: PepAccessContext,
  ): Promise<PepEvaluationResult> {
    const now = pepContext.now ?? new Date();
    const action = pepContext.action;

    // 1. Load document with classification and current version
    const document = await this.database.document.findUnique({
      where: { id: documentId },
      include: {
        classification_history: {
          where: { effective_to: null },
          include: { classification_levels: true },
        },
        current_version: true,
      },
    });

    if (!document) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document was not found.',
      });
    }

    if (document.status !== 'ACTIVE') {
      await this.recordDenyAudit(
        documentId,
        null,
        AppErrorCode.DOCUMENT_ACCESS_DENIED,
        'Document is not in ACTIVE state.',
        principal,
        context,
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: `Cannot access document in ${document.status} status.`,
      });
    }

    const currentVersion = document.current_version;
    if (!currentVersion || currentVersion.scan_status !== 'CLEAN') {
      throw new BadRequestException({
        errorCode: AppErrorCode.VERSION_NOT_CLEAN,
        message: 'Document has no active CLEAN version available.',
      });
    }

    const currentClassification = document.classification_history[0];
    const documentRank = currentClassification?.classification_levels?.rank ?? 0;
    const classAllowDownload =
      currentClassification?.classification_levels?.allow_download ?? false;
    const classRequireWatermark =
      currentClassification?.classification_levels?.require_watermark ?? true;

    // 2. Validate Access Grant: either explicit grantId or find active grant for user/roles
    let effectiveGrantId: string | null = pepContext.grantId ?? null;

    if (effectiveGrantId) {
      // Validate provided grant
      await this.grantsService.assertGrantValidForAccess(
        effectiveGrantId,
        principal.userId,
        action,
        now,
      );
    } else {
      // Find eligible grant for user or user's active roles
      effectiveGrantId = await this.resolveEligibleGrant(
        documentId,
        principal.userId,
        action,
        now,
        documentRank,
        document.owner_id === principal.userId,
        classAllowDownload,
      );
      if (!effectiveGrantId) {
        await this.recordDenyAudit(
          documentId,
          null,
          AppErrorCode.DOCUMENT_ACCESS_DENIED,
          'No valid active grant found for this user and action.',
          principal,
          context,
        );
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: `No active grant found providing ${action} permission for this document.`,
        });
      }
    }

    // 3. Check Classification Download Policy
    if (action === 'DOWNLOAD' && !classAllowDownload) {
      await this.recordDenyAudit(
        documentId,
        effectiveGrantId,
        AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        'Classification level forbids download.',
        principal,
        context,
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        message: 'This document classification level does not allow downloads.',
      });
    }

    // 4. Run PDP (ABAC) Evaluation
    const subjectAttributes = await this.buildSubjectAttributes(principal.userId, now);
    const resourceAttributes = {
      classificationRank: documentRank,
      departmentId: document.department_id?.toString() ?? null,
      documentStatus: document.status,
      ownerId: document.owner_id.toString(),
      category: null,
      status: document.status,
    };

    const abacResult = await this.abac.evaluate({
      resourceType: 'DOCUMENT',
      action,
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
      await this.recordDenyAudit(
        documentId,
        effectiveGrantId,
        AppErrorCode.POLICY_DENIED,
        abacResult.reasonCode,
        principal,
        context,
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.POLICY_DENIED,
        message: `Access denied by policy: ${abacResult.reasonCode}`,
      });
    }

    // 5. Enforce Obligations
    const obligations = abacResult.obligations ?? [];
    if (action === 'DOWNLOAD' && obligations.some((o) => o.type === 'FORBID_DOWNLOAD')) {
      await this.recordDenyAudit(
        documentId,
        effectiveGrantId,
        AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        'Policy obligation forbids download.',
        principal,
        context,
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
        message: 'Policy obligation forbids downloading this document.',
      });
    }

    const watermarkRequired =
      classRequireWatermark || obligations.some((o) => o.type === 'REQUIRE_WATERMARK');

    // 6. Create AccessSession when PERMIT
    const sessionId = randomUUID();
    await this.database.accessSession.create({
      data: {
        id: sessionId,
        access_grant_id: effectiveGrantId,
        document_version_id: currentVersion.id,
        user_id: principal.userId,
        ip_address: context.ip,
        user_agent: context.userAgent ?? null,
        device_fingerprint: pepContext.deviceFingerprint ?? null,
        status: 'ACTIVE',
        started_at: now,
        last_activity_at: now,
      },
    });

    // 7. Audit log ACCESS_PERMITTED
    await this.audit.record(
      {
        action: 'ACCESS_PERMITTED',
        outcome: 'SUCCESS',
        documentId,
        sessionId,
        objectId: effectiveGrantId,
        details: {
          action,
          versionNo: currentVersion.version_no,
          watermarkRequired,
          obligations: obligations.map((o) => o.type).join(','),
        },
      },
      principal,
      context,
    );

    return {
      sessionId,
      documentId,
      documentTitle: document.title,
      documentCode: document.document_code,
      documentVersionId: currentVersion.id,
      versionNo: currentVersion.version_no,
      grantId: effectiveGrantId,
      watermarkRequired,
      allowDownload: classAllowDownload,
      classificationRank: documentRank,
      obligations: obligations.map((o) => o.type),
    };
  }

  /**
   * Find an eligible active grant for user directly or through user's active roles.
   */
  private async resolveEligibleGrant(
    documentId: string,
    userId: bigint,
    action: 'VIEW' | 'DOWNLOAD',
    now: Date,
    documentRank: number,
    isOwner = false,
    classAllowDownload = true,
  ): Promise<string | null> {
    // 1. Direct USER grant
    const directGrant = await this.database.accessGrant.findFirst({
      where: {
        document_id: documentId,
        principal_type: 'USER',
        principal_user_id: userId,
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
        access_grant_permissions: {
          some: { permission: action },
        },
      },
      select: { id: true },
    });

    if (directGrant) {
      // Check clearance
      const hasClearance = await this.checkUserClearance(userId, documentRank, now);
      if (hasClearance) return directGrant.id;
    }

    // 2. ROLE grants through user's currently active roles
    const userRoles = await this.database.userRole.findMany({
      where: {
        user_id: userId,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { is_active: true },
      },
      select: { role_id: true },
    });

    if (userRoles.length > 0) {
      const roleIds = userRoles.map((r) => r.role_id);
      const roleGrant = await this.database.accessGrant.findFirst({
        where: {
          document_id: documentId,
          principal_type: 'ROLE',
          principal_role_id: { in: roleIds },
          status: 'ACTIVE',
          valid_from: { lte: now },
          valid_until: { gt: now },
          access_grant_permissions: {
            some: { permission: action },
          },
        },
        select: { id: true },
      });

      if (roleGrant) {
        // Even for ROLE grant, verify individual user clearance (D-BR04)
        const hasClearance = await this.checkUserClearance(userId, documentRank, now);
        if (hasClearance) return roleGrant.id;
      }
    }

    // 3. Document Owner access (UC20 & UC21: Owner can view/download own document with clearance)
    if (isOwner) {
      const hasClearance = await this.checkUserClearance(userId, documentRank, now);
      if (!hasClearance) return null;
      if (action === 'DOWNLOAD' && !classAllowDownload) return null;

      const existingOwnerGrant = await this.database.accessGrant.findFirst({
        where: {
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: userId,
          status: 'ACTIVE',
          valid_from: { lte: now },
          valid_until: { gt: now },
        },
        include: { access_grant_permissions: true },
      });

      if (existingOwnerGrant) {
        const perms = existingOwnerGrant.access_grant_permissions.map((p) => p.permission);
        if (!perms.includes(action)) {
          await this.database.accessGrantPermission.create({
            data: { access_grant_id: existingOwnerGrant.id, permission: action },
          });
        }
        return existingOwnerGrant.id;
      }

      const grantId = randomUUID();
      const validUntil = new Date(now.getTime() + 365 * 86400000);
      const permissions: ('VIEW' | 'DOWNLOAD')[] = ['VIEW'];
      if (classAllowDownload) permissions.push('DOWNLOAD');

      await this.database.accessGrant.create({
        data: {
          id: grantId,
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: userId,
          source: 'DIRECT',
          status: 'ACTIVE',
          valid_from: now,
          valid_until: validUntil,
          granted_by: userId,
          access_grant_permissions: {
            createMany: {
              data: permissions.map((p) => ({ permission: p })),
            },
          },
        },
      });
      return grantId;
    }

    return null;
  }

  private async checkUserClearance(
    userId: bigint,
    documentRank: number,
    now: Date,
  ): Promise<boolean> {
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

    const rank = clearance?.attribute_options?.numeric_rank ?? 0;
    return rank >= documentRank;
  }

  private async buildSubjectAttributes(
    userId: bigint,
    now: Date,
  ): Promise<{
    clearanceRank: number | null;
    departmentId: string | null;
    employmentStatus: string | null;
    projects: string[];
  }> {
    const user = await this.database.user?.findUnique?.({
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

  private async recordDenyAudit(
    documentId: string,
    grantId: string | null,
    reasonCode: string,
    reasonMessage: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    try {
      await this.audit.record(
        {
          action: 'ACCESS_DENIED',
          outcome: 'DENIED',
          documentId,
          objectId: grantId,
          reasonCode,
          details: { message: reasonMessage },
        },
        principal,
        context,
      );
    } catch (auditErr) {
      this.logger.error(`Failed to record access deny audit: ${auditErr}`);
    }
  }
}
