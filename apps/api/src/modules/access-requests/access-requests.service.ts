/**
 * Module: Quản lý Vòng đời Yêu cầu Xin Cấp Quyền Truy cập Tài liệu (Access Request Workflow Service)
 * Algorithm / Thuật toán: Máy trạng thái hữu hạn đơn hướng (`PENDING` -> `APPROVED` | `REJECTED` | `CANCELLED`)
 *   kết hợp kiểm tra tiền điều kiện Bell-LaPadula, chống dò quét tài liệu ẩn (`discoverable`),
 *   ngăn trùng lặp yêu cầu chờ duyệt và khóa phân tán Redlock khi ra quyết định phê duyệt.
 */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateAccessRequestInput,
  type DecideAccessRequestInput,
  type ListAccessRequestsInput,
} from '@sda/contracts';
import { AccessGrantAuditService } from '../access-grants/access-grant-audit.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RedlockService } from '../concurrency/redlock.service.js';
import { executeAccessRequestDecision } from './access-request-decision.helper.js';
import {
  mapAccessRequestDetail,
  validateCreateAccessRequestPreconditions,
} from './access-request-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AccessRequestDetail {
  id: string;
  documentId: string;
  documentTitle: string;
  documentCode?: string | null | undefined;
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

  constructor(
    private readonly audit: AccessGrantAuditService,
    private readonly grantsService: AccessGrantsService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly redlock?: RedlockService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * UC12: Algorithm / Thuật toán: Khởi Tạo Yêu Cầu Truy Cập Kèm Sàng Lọc Độ Mật & Chống Trùng Lặp.
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
    );

    const requestId = randomUUID();
    const created = await this.database.$transaction(async (tx) => {
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
          documents: true,
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

    return mapAccessRequestDetail(created, input.requestedAction);
  }

  /**
   * UC13 & UC15: Algorithm / Thuật toán: Truy Vấn Phân Trang Song Song Theo Góc Nhìn Vai Trò (`my` / `incoming`).
   */
  async listRequests(
    principal: AuthPrincipal,
    input: ListAccessRequestsInput,
  ): Promise<{ data: AccessRequestDetail[]; total: number }> {
    const where: Record<string, unknown> = {};
    if (input.status) where['status'] = input.status;
    where[input.scope === 'incoming' ? 'documents' : 'requester_id'] =
      input.scope === 'incoming' ? { owner_id: principal.userId } : principal.userId;

    const [rows, total] = await Promise.all([
      this.database.accessRequest.findMany({
        where,
        include: {
          documents: true,
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

    return { data: rows.map((req) => mapAccessRequestDetail(req)), total };
  }

  /**
   * UC14: Algorithm / Thuật toán: Chuyển Trạng Thái Hủy Yêu Cầu Của Người Gửi (`PENDING` -> `CANCELLED`).
   */
  async cancelRequest(
    id: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ id: string; status: string }> {
    const now = new Date();
    const request = await this.database.accessRequest.findUnique({ where: { id } });

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
      await tx.accessRequest.update({
        where: { id },
        data: {
          status: 'CANCELLED',
          cancelled_at: now,
          updated_at: now,
          version: { increment: 1 },
        },
      });
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

    return { id, status: 'CANCELLED' };
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
      });

    return this.redlock
      ? await this.redlock.withLock(`access-request:decision:${id}`, 5000, run)
      : await run();
  }
}
