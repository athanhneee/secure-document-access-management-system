/**
 * Module: Quản lý Vòng đời Yêu cầu Xin Cấp Quyền Truy cập Tài liệu (Access Request Workflow Service)
 * Algorithm / Thuật toán: Máy trạng thái hữu hạn đơn hướng (`PENDING` -> `APPROVED` | `REJECTED` | `CANCELLED`)
 *   kết hợp kiểm tra tiền điều kiện Bell-LaPadula, chống dò quét tài liệu ẩn (`discoverable`),
 *   ngăn trùng lặp yêu cầu chờ duyệt và khóa phân tán Redlock khi ra quyết định phê duyệt.
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  type CreateAccessRequestInput,
  type DecideAccessRequestInput,
  type ListAccessRequestsInput,
} from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { AccessGrantAuditService } from '../access-grants/access-grant-audit.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RedlockService } from '../concurrency/redlock.service.js';
import { NotificationsService } from '../notifications/notifications.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import { executeAccessRequestDecision } from './access-request-decision.helper.js';
import {
  notifyOwnerOfAccessRequestCancelled,
  notifyOwnerOfAccessRequestCreated,
} from './access-request-notification.helper.js';
import {
  mapAccessRequestDetail,
  validateCreateAccessRequestPreconditions,
} from './access-request-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExistingActiveGrantSummary {
  grantId: string;
  permissions: ('VIEW' | 'DOWNLOAD')[];
  validFrom: string;
  validUntil: string;
}

export interface AccessRequestDetail {
  id: string;
  documentId: string;
  documentTitle: string;
  documentCode?: string | null | undefined;
  documentClassificationCode?: string | null | undefined;
  documentRetentionUntil?: string | null | undefined;
  documentDefaultViewDays?: number | null | undefined;
  documentAllowDownload?: boolean | undefined;
  existingActiveGrant?: ExistingActiveGrantSummary | null | undefined;
  requestorId: string;
  requestorName: string;
  requestorUsername: string;
  requestorDepartment: string;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  justification: string;
  status: string;
  createdAt: string;
  requestedFrom: string;
  requestedUntil: string;
  decidedAt?: string | null | undefined;
  decisionNote?: string | null | undefined;
}

@Injectable()
export class AccessRequestsService {
  private readonly database: PrismaClient;
  private readonly maxDurationDays: number;

  constructor(
    private readonly audit: AccessGrantAuditService,
    private readonly grantsService: AccessGrantsService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly redlock?: RedlockService,
    @Optional() private readonly realtime?: RealtimeEventsService,
    @Optional() private readonly notifications?: NotificationsService,
    @Optional() private readonly config?: AppConfigService,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.maxDurationDays =
      this.config?.get?.('GRANT_MAX_DURATION_DAYS') ?? DEFAULT_GRANT_MAX_DURATION_DAYS;
  }

  /**
   * UC12: Algorithm / Thuật toán: Khởi Tạo Yêu Cầu Truy Cập Kèm Sàng Lọc Độ Mật, Trần Thời Hạn & Chống Trùng Lặp.
   */
  async createRequest(
    input: CreateAccessRequestInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<AccessRequestDetail> {
    const now = new Date();
    const { requestedFrom, requestedUntil } = await validateCreateAccessRequestPreconditions(
      this.database,
      input,
      principal,
      now,
      this.maxDurationDays,
    );

    const requestId = randomUUID();
    const created = await this.database.$transaction(async (tx) => {
      // MED-08: Khóa tư vấn giao dịch theo cặp `(documentId, requesterId)` và kiểm tra lại `PENDING` trong giao dịch chống gửi trùng khi double-click.
      if (typeof (tx as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function') {
        await (
          tx as unknown as {
            $executeRawUnsafe: (sql: string, ...args: unknown[]) => Promise<unknown>;
          }
        ).$executeRawUnsafe(
          'SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))',
          input.documentId,
          `access-req:${principal.userId.toString()}`,
        );
      }
      if (typeof tx.accessRequest?.findFirst === 'function') {
        const duplicate = await tx.accessRequest.findFirst({
          where: {
            document_id: input.documentId,
            requester_id: principal.userId,
            status: 'PENDING',
          },
          select: { id: true },
        });
        if (duplicate) {
          throw new ConflictException({
            errorCode: AppErrorCode.ACCESS_REQUEST_DUPLICATE,
            message: 'You already have a pending access request for this document.',
          });
        }
      }

      const req = await tx.accessRequest.create({
        data: {
          id: requestId,
          document_id: input.documentId,
          requester_id: principal.userId,
          reason: input.reason.trim(),
          requested_from: requestedFrom,
          requested_until: requestedUntil,
          status: 'PENDING',
          submitted_at: now,
          updated_at: now,
          version: 0,
          access_request_permissions: { create: { permission: input.requestedAction } },
        },
        include: {
          documents: {
            include: {
              classification_history: {
                where: { effective_to: null },
                include: { classification_levels: true },
              },
            },
          },
          users: { include: { departments: true } },
          access_request_permissions: true,
        },
      });

      await this.audit.record(
        {
          action: 'ACCESS_REQUEST_CREATED',
          outcome: 'SUCCESS',
          objectId: requestId,
          documentId: input.documentId,
          details: {
            requesterId: principal.userId.toString(),
            requestedAction: input.requestedAction,
            reason: input.reason.trim(),
          },
        },
        principal,
        context,
        tx,
      );
      return req;
    });

    const detail = mapAccessRequestDetail(created, input.requestedAction);
    const ownerId = (created as { documents?: { owner_id?: bigint | null } }).documents?.owner_id;
    await notifyOwnerOfAccessRequestCreated({
      notifications: this.notifications,
      ownerId,
      requesterId: principal.userId,
      requestId: detail.id,
      documentId: detail.documentId,
      documentTitle: detail.documentTitle,
      documentCode: detail.documentCode,
      requestorName: detail.requestorName,
      requestorUsername: detail.requestorUsername,
      requestorDepartment: detail.requestorDepartment,
      requestedAction: detail.requestedAction,
      justification: detail.justification,
    });
    const targets = [principal.userId.toString(), ...(ownerId ? [ownerId.toString()] : [])];
    this.realtime?.publish({
      type: 'ACCESS_REQUEST_UPDATED',
      targetUserIds: targets,
      payload: {
        id: detail.id,
        status: detail.status,
        documentId: detail.documentId,
        action: 'CREATED',
      },
    });
    return detail;
  }

  /**
   * UC13 & UC15: Algorithm / Thuật toán: Truy Vấn Phân Trang Song Song Theo Góc Nhìn Vai Trò (`my` / `incoming` / `all`) Có Ràng Buộc Quyền RBAC.
   */
  async listRequests(
    principal: AuthPrincipal,
    input: ListAccessRequestsInput,
  ): Promise<{ data: AccessRequestDetail[]; total: number }> {
    const where: Record<string, unknown> = {};
    if (input.status) where['status'] = input.status;

    const hasAuthz = Boolean(
      this.authorization && typeof this.authorization.hasPermission === 'function',
    );

    if (input.scope === 'incoming') {
      if (hasAuthz) {
        const canDecide = await this.authorization!.hasPermission(
          principal,
          'ACCESS_REQUEST',
          'DECIDE',
          { anyScope: true },
        );
        if (!canDecide) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.FORBIDDEN,
            message: 'ACCESS_REQUEST:DECIDE permission is required to view incoming requests.',
          });
        }
      }
      where['documents'] = { owner_id: principal.userId };
    } else if (input.scope === 'all') {
      let canViewOwn = true;
      let canDecide = true;
      if (hasAuthz) {
        [canViewOwn, canDecide] = await Promise.all([
          this.authorization!.hasPermission(principal, 'ACCESS_REQUEST', 'VIEW_OWN', {
            anyScope: true,
          }),
          this.authorization!.hasPermission(principal, 'ACCESS_REQUEST', 'DECIDE', {
            anyScope: true,
          }),
        ]);
      } else if (Array.isArray(principal.roles) && principal.roles.length > 0) {
        const isPureReader = principal.roles.every((r) => r === 'DOCUMENT_READER');
        canDecide = !isPureReader;
      }

      const orBranches: Record<string, unknown>[] = [];
      if (canViewOwn) {
        orBranches.push({ requester_id: principal.userId });
      }
      if (canDecide) {
        orBranches.push({ documents: { owner_id: principal.userId } });
      }
      if (orBranches.length === 0) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message: 'Insufficient permissions to list access requests.',
        });
      }
      where['OR'] = orBranches;
    } else {
      if (hasAuthz) {
        const canViewOwn = await this.authorization!.hasPermission(
          principal,
          'ACCESS_REQUEST',
          'VIEW_OWN',
          { anyScope: true },
        );
        if (!canViewOwn) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.FORBIDDEN,
            message: 'ACCESS_REQUEST:VIEW_OWN permission is required to view own requests.',
          });
        }
      }
      where['requester_id'] = principal.userId;
    }

    const [rows, total] = await Promise.all([
      this.database.accessRequest.findMany({
        where,
        include: {
          documents: {
            include: {
              classification_history: {
                where: { effective_to: null },
                include: { classification_levels: true },
              },
            },
          },
          users: { include: { departments: true } },
          access_request_permissions: true,
          access_request_decisions: true,
        },
        orderBy: { submitted_at: 'desc' },
        skip: (input.page - 1) * input.pageSize,
        take: input.pageSize,
      }),
      this.database.accessRequest.count({ where }),
    ]);

    // Thuật toán: Gom lô truy vấn quyền hiện hành (`O(1)` truy vấn SQL) cho các dòng thuộc tài liệu chủ sở hữu quản lý (`incoming` hoặc nhánh chủ sở hữu trong `all`).
    const activeGrantByPair = new Map<string, ExistingActiveGrantSummary>();
    const incomingRows =
      input.scope === 'incoming'
        ? rows
        : input.scope === 'all'
          ? rows.filter(
              (r) => (r.documents as { owner_id?: bigint | null })?.owner_id === principal.userId,
            )
          : [];
    if (incomingRows.length > 0 && typeof this.database?.accessGrant?.findMany === 'function') {
      const now = new Date();
      const docIds = [...new Set(incomingRows.map((r) => r.document_id))];
      const requesterIds = [...new Set(incomingRows.map((r) => r.requester_id))];
      const existingGrants = await this.database.accessGrant.findMany({
        where: {
          document_id: { in: docIds },
          principal_type: 'USER',
          principal_user_id: { in: requesterIds },
          status: 'ACTIVE',
          valid_until: { gt: now },
        },
        include: { access_grant_permissions: true },
        orderBy: { valid_until: 'desc' },
      });
      for (const grant of existingGrants) {
        if (grant.principal_user_id === null) continue;
        const key = `${grant.document_id}:${grant.principal_user_id.toString()}`;
        if (activeGrantByPair.has(key)) continue;
        const perms = [
          ...new Set(
            grant.access_grant_permissions
              .map((p) => p.permission)
              .filter((p): p is 'VIEW' | 'DOWNLOAD' => p === 'VIEW' || p === 'DOWNLOAD'),
          ),
        ];
        activeGrantByPair.set(key, {
          grantId: grant.id,
          permissions: perms.length > 0 ? perms : ['VIEW'],
          validFrom: grant.valid_from.toISOString(),
          validUntil: grant.valid_until.toISOString(),
        });
      }
    }

    return {
      data: rows.map((req) => {
        const pairKey = `${req.document_id}:${req.requester_id.toString()}`;
        const isOwnedRow =
          input.scope === 'incoming' ||
          (input.scope === 'all' &&
            (req.documents as { owner_id?: bigint | null })?.owner_id === principal.userId);
        const existingGrant = isOwnedRow ? (activeGrantByPair.get(pairKey) ?? null) : undefined;
        return mapAccessRequestDetail(req, undefined, existingGrant);
      }),
      total,
    };
  }

  /**
   * UC14: Algorithm / Thuật toán: Chuyển Trạng Thái Hủy Yêu Cầu Của Người Gửi Có Khóa Redlock & CAS Nguyên Tử (`PENDING` -> `CANCELLED`).
   */
  async cancelRequest(
    id: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ id: string; status: string }> {
    const runCancel = async (): Promise<{ id: string; status: string }> => {
      const now = new Date();
      const request = await this.database.accessRequest.findUnique({
        where: { id },
        include: {
          documents: { select: { owner_id: true, title: true, document_code: true } },
          users: { select: { full_name: true, username: true } },
        },
      });

      if (!request) {
        throw new NotFoundException({
          errorCode: AppErrorCode.ACCESS_REQUEST_NOT_FOUND,
          message: 'Access request was not found.',
        });
      }
      if (request.requester_id !== principal.userId) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message: 'You can only cancel your own access requests.',
        });
      }
      if (request.status !== 'PENDING') {
        throw new BadRequestException({
          errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
          message: `Cannot cancel request in ${request.status} status.`,
        });
      }

      await this.database.$transaction(async (tx) => {
        // CONFLICT-RESOLVED: Bọc Redlock cùng khóa `access-request:decision:${id}` và dùng CAS `status = 'PENDING'` để ngăn ghi đè yêu cầu vừa được phê duyệt (HIGH-11).
        if (typeof tx.accessRequest.updateMany === 'function') {
          const updated = await tx.accessRequest.updateMany({
            where: { id, requester_id: principal.userId, status: 'PENDING' },
            data: {
              status: 'CANCELLED',
              cancelled_at: now,
              updated_at: now,
              version: { increment: 1 },
            },
          });
          if (updated.count === 0) {
            throw new BadRequestException({
              errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
              message: 'Access request was concurrently decided or cancelled.',
            });
          }
        } else {
          const current = await tx.accessRequest.findUnique({ where: { id } });
          if (!current || current.status !== 'PENDING') {
            throw new BadRequestException({
              errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
              message: 'Access request was concurrently decided or cancelled.',
            });
          }
          await tx.accessRequest.update({
            where: { id },
            data: {
              status: 'CANCELLED',
              cancelled_at: now,
              updated_at: now,
              version: { increment: 1 },
            },
          });
        }
        await this.audit.record(
          {
            action: 'ACCESS_REQUEST_CANCELLED',
            outcome: 'SUCCESS',
            objectId: id,
            documentId: request.document_id,
            details: { requesterId: principal.userId.toString() },
          },
          principal,
          context,
          tx,
        );
      });

      const requestMeta = request as {
        documents?: {
          owner_id?: bigint | null;
          title?: string | null;
          document_code?: string | null;
        } | null;
        users?: { full_name?: string | null; username?: string | null } | null;
      };
      const ownerId = requestMeta.documents?.owner_id;
      await notifyOwnerOfAccessRequestCancelled({
        notifications: this.notifications,
        ownerId,
        requesterId: principal.userId,
        requestId: id,
        documentId: request.document_id,
        documentTitle: requestMeta.documents?.title,
        documentCode: requestMeta.documents?.document_code,
        requestorName: requestMeta.users?.full_name || principal.username,
        requestorUsername: requestMeta.users?.username || principal.username,
      });
      this.realtime?.publish({
        type: 'ACCESS_REQUEST_UPDATED',
        targetUserIds: [principal.userId.toString(), ...(ownerId ? [ownerId.toString()] : [])],
        payload: {
          id,
          status: 'CANCELLED',
          documentId: request.document_id,
          action: 'CANCELLED',
        },
      });
      return { id, status: 'CANCELLED' };
    };

    return this.redlock
      ? await this.redlock.withLock(`access-request:decision:${id}`, 5000, runCancel)
      : await runCancel();
  }

  /**
   * UC16: Algorithm / Thuật toán: Máy Trạng Thái Ra Quyết Định Phê Duyệt Có Khóa Phân Tán Redlock (`PENDING` -> `APPROVED` | `REJECTED`).
   */
  async decideRequest(
    id: string,
    input: DecideAccessRequestInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ id: string; status: string; grantId?: string }> {
    const run = () =>
      executeAccessRequestDecision({
        id,
        input,
        principal,
        context,
        database: this.database,
        audit: this.audit,
        grantsService: this.grantsService,
        realtime: this.realtime,
        notifications: this.notifications,
      });

    return this.redlock
      ? await this.redlock.withLock(`access-request:decision:${id}`, 5000, run)
      : await run();
  }
}
