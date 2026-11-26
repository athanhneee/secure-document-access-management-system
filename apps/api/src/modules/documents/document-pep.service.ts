/**
 * Module: Document Policy Enforcement Point (PEP) Service
 * Thuật toán: Đường Ống Thẩm Định Thực Thi Chính Sách Đa Tầng Zero-Trust (`DocumentPepService`).
 *   1. Kiểm tra phân tách nhiệm vụ bất biến (SoD) ngăn tài khoản quản trị kỹ thuật và kiểm toán viên truy cập nội dung tài liệu.
 *   2. Xác minh tài liệu trạng thái `ACTIVE`, phiên bản hiện hành `CLEAN`, quyền cấp phát và trần độ mật Bell-LaPadula.
 *   3. Đánh giá ABAC PDP, cưỡng chế nghĩa vụ (`REQUIRE_MFA`, `FORBID_DOWNLOAD`, `REQUIRE_WATERMARK`, `MAX_SESSION_MINUTES`) và lưu trạng thái phiên phân tán qua `DistributedStateService`.
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
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import {
  ensurePermittedOwnerSystemGrant,
  verifyAndResolveEffectiveGrant,
} from './pep-clearance.helper.js';
import {
  hasPrivilegedNonBusinessCapability,
  isRestrictedNonBusinessRole,
  recordPepDenyAudit,
  type ActiveSessionPolicy,
  type PepAccessContext,
  type PepEvaluationResult,
} from './pep-context-builder.js';
import {
  evaluatePepPolicyAndObligations,
  finalizePermittedAccessSession,
  SESSION_POLICY_NAMESPACE,
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
  private readonly stateStore: DistributedStateService;

  constructor(
    private readonly abac: AbacService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
    @Optional() private readonly realtime?: RealtimeEventsService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.stateStore =
      stateStore ??
      new DistributedStateService(config instanceof AppConfigService ? config : undefined);
  }

  /**
   * Thuật toán: Truy vấn bản chụp chính sách phiên từ kho phân tán `DistributedStateService`.
   */
  async getSessionPolicy(sessionId: string): Promise<ActiveSessionPolicy | null> {
    return await this.stateStore.getJson<ActiveSessionPolicy>(SESSION_POLICY_NAMESPACE, sessionId);
  }

  /**
   * Thuật toán: Xóa tức thì bộ đệm chính sách phiên trên kho phân tán khi phiên bị thu hồi hoặc chấm dứt.
   */
  async invalidateSessionPolicy(sessionId: string): Promise<void> {
    await this.stateStore.deleteKey(SESSION_POLICY_NAMESPACE, sessionId);
  }

  /**
   * Thuật toán: Cưỡng Chế Nghĩa Vụ Phiên Hoạt Động Theo Cơ Chế Fail-Closed Xuyên Bản Sao (`enforceSessionPolicy`)
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
      stateStore: this.stateStore,
      database: this.database,
      abac: this.abac,
      config: this.config,
    });
  }

  /**
   * Thuật toán: Đường Ống Thẩm Định Mở Phiên Truy Cập Tài Liệu Đa Tầng (`enforceAccess`)
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

    if (
      isRestrictedNonBusinessRole(principal) ||
      (await hasPrivilegedNonBusinessCapability(this.database, principal, now))
    ) {
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
    if (!document || document.status === 'DELETED') {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document was not found.',
      });
    }
    if (document.status !== 'ACTIVE') {
      await deny(null, AppErrorCode.DOCUMENT_ACCESS_DENIED, 'Document is not in ACTIVE state.');
      if (document.owner_id !== principal.userId) {
        throw new NotFoundException({
          errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
          message: 'Document was not found.',
        });
      }
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

    const isOwner = document.owner_id === principal.userId;
    const {
      effectiveGrantId: candidateGrantId,
      grantPermitsDownload,
      pendingOwnerGrantProvision,
    } = await verifyAndResolveEffectiveGrant({
      database: this.database,
      grantsService: this.grantsService,
      documentId,
      documentDepartmentId: document.department_id,
      requestedGrantId: pepContext.grantId,
      userId: principal.userId,
      action,
      now,
      documentRank,
      isOwner,
      classAllowDownload,
      documentRetentionUntil: (document as { retention_until?: Date | null }).retention_until,
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
      deviceFingerprint: pepContext.deviceFingerprint,
      documentRank,
      departmentId: document.department_id,
      documentStatus: document.status,
      ownerId: document.owner_id,
      categoryCode,
      classRequireWatermark,
      effectiveGrantId: candidateGrantId,
      deny,
    });

    const effectiveGrantId =
      pendingOwnerGrantProvision || candidateGrantId === null
        ? await ensurePermittedOwnerSystemGrant({
            database: this.database,
            documentId,
            userId: principal.userId,
            action,
            now,
            classAllowDownload,
            documentRetentionUntil: (document as { retention_until?: Date | null }).retention_until,
          })
        : candidateGrantId;

    const sessionId = await finalizePermittedAccessSession({
      database: this.database,
      audit: this.audit,
      stateStore: this.stateStore,
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

    this.realtime?.publish({
      type: 'ACCESS_SESSION_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId: document.department_id?.toString() ?? null,
      payload: { id: sessionId, documentId, status: 'ACTIVE', action: 'STARTED' },
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
      allowDownload:
        classAllowDownload && grantPermitsDownload && !policyOutcome.forbidDownloadObligation,
      classificationRank: documentRank,
      obligations: policyOutcome.obligationTypes,
    };
  }
}
