/**
 * Module: Quản lý Cấp quyền Truy cập Tài liệu Có Thời hạn (Time-Bound Access Grants Service)
 * Algorithm / Thuật toán cốt lõi:
 *   - Khóa đồng thời hai tầng: Redlock kết hợp giao dịch `Serializable` và `SELECT ... FOR UPDATE`.
 *   - Hợp nhất khoảng hiệu lực (Interval Coalescing) cho các quyền trùng tập hợp.
 *   - Kiểm tra bất biến đa cấp: Phân tách nhiệm vụ (SoD), Bell-LaPadula (`userRank >= documentRank`),
 *     đánh giá chính sách ABAC theo ngữ cảnh mạng CIDR và khoảng nửa mở `[valid_from, valid_until)`.
 *   - Thu hồi tức thời kèm đóng phiên truy cập liên đới và vô hiệu hóa bộ nhớ đệm phân quyền.
 */
import { Injectable, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateAccessGrantInput,
  type ListAccessGrantsInput,
  type RevokeAccessGrantInput,
} from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { AbacService } from '../abac/abac.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RedlockService } from '../concurrency/redlock.service.js';
import { NotificationsService } from '../notifications/notifications.service.js';
import { AuthorizationCache } from '../rbac/authorization-cache.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { AccessGrantAuditService } from './access-grant-audit.service.js';
import { toGrantDetail, type GrantDetail, type GrantListResult } from './access-grants.types.js';
import { verifyGrantValidForAccess } from './grant-enforcement.helper.js';
import { executeRevokeGrantWorkflow } from './grant-revocation.helper.js';
import { executeCreateOrExtendGrantTx } from './grant-transaction.helper.js';
import { validateCreateGrantPreconditions } from './grant-validation.helper.js';

export type { GrantDetail, GrantListResult } from './access-grants.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AccessGrantsService {
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
    @Optional() private readonly notifications?: NotificationsService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.maxDurationDays = this.config.get('GRANT_MAX_DURATION_DAYS');
  }

  /**
   * Algorithm / Thuật toán: Cấp Quyền Truy Cập Có Thời Hạn Kèm Hợp Nhất Khoảng Hiệu Lực & Khóa Phân Tán Hai Tầng.
   */
  async createGrant(
    input: CreateAccessGrantInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<GrantDetail> {
    const now = new Date();
    const { validFrom, validUntil, maxMs } = await validateCreateGrantPreconditions({
      input,
      principal,
      context,
      now,
      maxDurationDays: this.maxDurationDays,
      database: this.database,
      authorization: this.authorization,
      abac: this.abac,
      config: this.config,
    });

    const runTx = () =>
      executeCreateOrExtendGrantTx({
        input,
        principal,
        context,
        now,
        validFrom,
        validUntil,
        maxMs,
        maxDurationDays: this.maxDurationDays,
        database: this.database,
        audit: this.audit,
      });

    const principalId =
      input.principalType === 'USER' ? input.principalUserId : input.principalRoleId;
    const lockResource = `access-grant:${input.documentId}:${input.principalType}:${principalId}`;

    const created = this.redlock
      ? await this.redlock.withLock(lockResource, 5000, runTx)
      : await runTx();

    if (this.notifications && created.principalType === 'USER' && created.principalUserId) {
      try {
        await this.notifications.sendNotification({
          recipientId: BigInt(created.principalUserId),
          notificationType: 'ACCESS_GRANT_ISSUED',
          title: 'Bạn vừa được cấp quyền truy cập tài liệu',
          body: `Quyền truy cập (${created.permissions.join(', ')}) đối với tài liệu ${created.documentId} có hiệu lực đến ${created.validUntil}.`,
          relatedObjectType: 'ACCESS_GRANT',
          relatedObjectId: created.id,
          deduplicationKey: `ACCESS_GRANT_ISSUED:${created.principalUserId}:${created.id}:v${created.version}`,
          payload: {
            grantId: created.id,
            documentId: created.documentId,
            permissions: created.permissions,
            validUntil: created.validUntil,
          },
        });
      } catch {
        // Non-fatal post-commit notification dispatch
      }
    }

    return created;
  }

  /**
   * Algorithm / Thuật toán: Thu Hồi Quyền Truy Cập Bất Biến Lịch Sử Kèm Đóng Phiên Liên Đới (Cascading Grant Revocation).
   */
  async revokeGrant(
    grantId: string,
    input: RevokeAccessGrantInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<GrantDetail> {
    return executeRevokeGrantWorkflow({
      grantId,
      input,
      principal,
      context,
      database: this.database,
      authorization: this.authorization,
      cache: this.cache,
      audit: this.audit,
      notifications: this.notifications,
    });
  }

  /**
   * Algorithm / Thuật toán: Truy Vấn Chi Tiết Quyền Truy Cập Chống Dò Quét Định Danh (Anti-Enumeration Visibility Check).
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

    return toGrantDetail(grant);
  }

  /**
   * Algorithm / Thuật toán: Phân Trang Đọc Trước N+1 Theo Phạm Vi Quyền Nhìn Thấy (Visibility-Scoped N+1 Lookahead Pagination).
   */
  async listGrants(
    input: ListAccessGrantsInput,
    principal: AuthPrincipal,
  ): Promise<GrantListResult> {
    const where: Record<string, unknown> = {};

    if (input.documentId) {
      const doc = await this.database.document.findUnique({
        where: { id: input.documentId },
        select: { owner_id: true, department_id: true },
      });
      if (!doc) {
        return { data: [], page: input.page, pageSize: input.pageSize, hasMore: false };
      }
      if (doc.owner_id !== principal.userId) {
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
      where['OR'] = [
        { documents: { owner_id: principal.userId } },
        { principal_user_id: principal.userId },
      ];
    }

    if (input.status) where['status'] = input.status;
    if (input.principalType) where['principal_type'] = input.principalType;

    const sortField =
      input.sort === 'granted_at'
        ? 'granted_at'
        : input.sort === 'valid_until'
          ? 'valid_until'
          : 'status';

    const grants = await this.database.accessGrant.findMany({
      where,
      include: { access_grant_permissions: true },
      orderBy: [{ [sortField]: input.order }, { id: 'asc' }],
      skip: (input.page - 1) * input.pageSize,
      take: input.pageSize + 1,
    });

    return {
      data: grants.slice(0, input.pageSize).map(toGrantDetail),
      page: input.page,
      pageSize: input.pageSize,
      hasMore: grants.length > input.pageSize,
    };
  }

  /**
   * Algorithm / Thuật toán: Thẩm Định Hiệu Lực Quyền Truy Cập Thời Gian Thực (Real-Time Reference Monitor Grant Validation).
   */
  assertGrantValidForAccess(
    grantId: string,
    userId: bigint,
    requestedAction: 'VIEW' | 'DOWNLOAD',
    now: Date = new Date(),
    expectedDocumentId?: string,
  ) {
    return verifyGrantValidForAccess(
      this.database,
      grantId,
      userId,
      requestedAction,
      now,
      expectedDocumentId,
    );
  }
}
