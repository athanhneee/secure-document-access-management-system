/**
 * Module: Document Policy Enforcement Point (PEP) Service
 * Algorithm: Multi-layer zero-trust enforcement pipeline (SoD role guard -> ACTIVE document & CLEAN version ->
 *   explicit/resolved grant + Bell-LaPadula clearance -> ABAC PDP & obligation gate -> context-bound `AccessSession`),
 *   plus fail-closed multi-replica session obligation verification.
 */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AbacService } from '../abac/abac.service.js';
import { AppConfigService } from '../../config/config.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { verifyAndResolveEffectiveGrant } from './pep-clearance.helper.js';
import {
  isRestrictedNonBusinessRole,
  recordPepDenyAudit,
  type ActiveSessionPolicy,
  type PepAccessContext,
  type PepEvaluationResult,
} from './pep-context-builder.js';
import {
  evaluatePepPolicyAndObligations,
  finalizePermittedAccessSession,
} from './pep-obligations.helper.js';
import {
  resolveAndEnforceSessionPolicy,
  type SessionRecordForPolicyCheck,
} from './session-policy-resolver.helper.js';

export type {
  ActiveSessionPolicy,
  PepAccessContext,
  PepEvaluationResult,
} from './pep-context-builder.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class DocumentPepService {
  private readonly logger = new Logger(DocumentPepService.name);
  private readonly database: PrismaClient;
  // shortcut: 10,000 cached session policies (~2 MB) with fail-closed DB/audit rehydration on miss, move to Redis hash for shared L1 cache
  private readonly sessionPolicies = new Map<string, ActiveSessionPolicy>();

  constructor(
    private readonly abac: AbacService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly config?: AppConfigService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  getSessionPolicy(sessionId: string): ActiveSessionPolicy | undefined {
    return this.sessionPolicies.get(sessionId);
  }

  /**
   * Algorithm: Fail-Closed Active Session Obligation Enforcement
   * Validates in-memory or re-hydrated ABAC session duration (`MAX_SESSION_MINUTES`) and `FORBID_DOWNLOAD` obligations.
   */
  async enforceSessionPolicy(
    session: SessionRecordForPolicyCheck,
    requiredAction: 'VIEW' | 'DOWNLOAD',
    principal: AuthPrincipal,
    context: RequestContext,
    now = new Date(),
  ): Promise<ActiveSessionPolicy> {
    return resolveAndEnforceSessionPolicy({
      session,
      requiredAction,
      principal,
      context,
      now,
      sessionPolicies: this.sessionPolicies,
      database: this.database,
      abac: this.abac,
      config: this.config,
    });
  }

  /**
   * Algorithm: Multi-Layer Zero-Trust PEP Enforcement Pipeline
   */
  async enforceAccess(
    documentId: string,
    principal: AuthPrincipal,
    context: RequestContext,
    pepContext: PepAccessContext,
  ): Promise<PepEvaluationResult> {
    const now = pepContext.now ?? new Date();
    const action = pepContext.action;
    const deny = (grantId: string | null, reasonCode: string, reasonMessage: string) =>
      recordPepDenyAudit({
        audit: this.audit,
        logger: this.logger,
        documentId,
        grantId,
        reasonCode,
        reasonMessage,
        principal,
        context,
      });

    if (isRestrictedNonBusinessRole(principal.roles ?? [])) {
      await deny(
        pepContext.grantId ?? null,
        AppErrorCode.DOCUMENT_ACCESS_DENIED,
        'Separation of duties: technical admin and auditor roles cannot access document content.',
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Technical administrator and auditor accounts cannot access document content.',
      });
    }

    const document = await this.database.document.findUnique({
      where: { id: documentId },
      include: {
        classification_history: {
          where: { effective_to: null },
          include: { classification_levels: true, business_categories: true },
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
      await deny(null, AppErrorCode.DOCUMENT_ACCESS_DENIED, 'Document is not in ACTIVE state.');
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

    const effectiveGrantId = await verifyAndResolveEffectiveGrant({
      database: this.database,
      grantsService: this.grantsService,
      documentId,
      requestedGrantId: pepContext.grantId,
      userId: principal.userId,
      action,
      now,
      documentRank,
      isOwner: document.owner_id === principal.userId,
      classAllowDownload,
      deny,
    });

    const categoryCode =
      (currentClassification as { business_categories?: { code?: string } | null } | undefined)
        ?.business_categories?.code ?? null;
    const policyOutcome = await evaluatePepPolicyAndObligations({
      database: this.database,
      abac: this.abac,
      config: this.config,
      action,
      now,
      principal,
      context,
      documentRank,
      departmentId: document.department_id,
      documentStatus: document.status,
      ownerId: document.owner_id,
      categoryCode,
      classRequireWatermark,
      effectiveGrantId,
      deny,
    });

    const sessionId = await finalizePermittedAccessSession({
      database: this.database,
      audit: this.audit,
      sessionPolicies: this.sessionPolicies,
      documentId,
      effectiveGrantId,
      documentVersionId: currentVersion.id,
      versionNo: currentVersion.version_no,
      action,
      deviceFingerprint: pepContext.deviceFingerprint,
      now,
      principal,
      context,
      policyOutcome,
    });

    return {
      sessionId,
      documentId,
      documentTitle: document.title,
      documentCode: document.document_code,
      documentVersionId: currentVersion.id.toString(),
      versionNo: currentVersion.version_no,
      grantId: effectiveGrantId,
      watermarkRequired: policyOutcome.watermarkRequired,
      allowDownload: classAllowDownload && !policyOutcome.forbidDownloadObligation,
      classificationRank: documentRank,
      obligations: policyOutcome.obligationTypes,
    };
  }
}
