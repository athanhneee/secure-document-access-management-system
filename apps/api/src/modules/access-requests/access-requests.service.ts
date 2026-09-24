import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  ConflictException,
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

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AccessRequestDetail {
  id: string;
  documentId: string;
  documentTitle: string;
  documentCode?: string | null;
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
  decidedAt?: string | null;
  decisionNote?: string | null;
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
   * UC12: Reader creates an access request for a document.
   */
  async createRequest(
    input: CreateAccessRequestInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<AccessRequestDetail> {
    const now = new Date();
    const requestedFrom = input.requestedFrom ? new Date(input.requestedFrom) : now;
    const requestedUntil = input.requestedUntil
      ? new Date(input.requestedUntil)
      : new Date(now.getTime() + 7 * 86400000);

    if (requestedUntil <= requestedFrom) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
        message: 'requestedUntil must be after requestedFrom.',
      });
    }

    // 1. Verify document exists and is ACTIVE
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

    if (document.status !== 'ACTIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Cannot request access to a document that is not ACTIVE.',
      });
    }

    // 2. If DOWNLOAD requested, verify classification allows download
    const currentClassification = document.classification_history[0];
    if (input.requestedAction === 'DOWNLOAD') {
      if (currentClassification && !currentClassification.classification_levels.allow_download) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
          message: 'Document classification does not allow download.',
        });
      }
    }

    // 3. Prevent duplicate pending requests for the same user and document
    const existing = await this.database.accessRequest.findFirst({
      where: {
        document_id: input.documentId,
        requester_id: principal.userId,
        status: 'PENDING',
      },
    });

    if (existing) {
      throw new ConflictException({
        errorCode: AppErrorCode.ACCESS_REQUEST_DUPLICATE,
        message: 'You already have a pending access request for this document.',
      });
    }

    // 4. Create request in database transaction
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
          access_request_permissions: {
            create: {
              permission: input.requestedAction,
            },
          },
        },
        include: {
          documents: true,
          users: {
            include: { departments: true },
          },
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

    return {
      id: created.id,
      documentId: created.document_id,
      documentTitle: created.documents.title,
      documentCode: created.documents.document_code,
      requestorId: created.requester_id.toString(),
      requestorName: created.users.full_name || created.users.username,
      requestorUsername: created.users.username,
      requestorDepartment: created.users.departments?.name || 'Chung',
      requestedAction: input.requestedAction,
      justification: created.reason,
      status: created.status,
      createdAt: created.submitted_at.toISOString(),
      requestedFrom: created.requested_from.toISOString(),
      requestedUntil: created.requested_until.toISOString(),
    };
  }

  /**
   * UC13 & UC15: List access requests.
   * - Reader (scope='my'): Lists user's own requests.
   * - Owner (scope='incoming'): Lists requests for documents owned by caller.
   */
  async listRequests(
    principal: AuthPrincipal,
    input: ListAccessRequestsInput,
  ): Promise<{ data: AccessRequestDetail[]; total: number }> {
    const isOwnerScope = input.scope === 'incoming';

    const where: Record<string, unknown> = {};
    if (input.status) {
      where['status'] = input.status;
    }

    if (isOwnerScope) {
      where['documents'] = { owner_id: principal.userId };
    } else {
      where['requester_id'] = principal.userId;
    }

    const [rows, total] = await Promise.all([
      this.database.accessRequest.findMany({
        where,
        include: {
          documents: true,
          users: {
            include: { departments: true },
          },
          access_request_permissions: true,
          access_request_decisions: true,
        },
        orderBy: { submitted_at: 'desc' },
        skip: (input.page - 1) * input.pageSize,
        take: input.pageSize,
      }),
      this.database.accessRequest.count({ where }),
    ]);

    const data: AccessRequestDetail[] = rows.map((req) => ({
      id: req.id,
      documentId: req.document_id,
      documentTitle: req.documents.title,
      documentCode: req.documents.document_code,
      requestorId: req.requester_id.toString(),
      requestorName: req.users.full_name || req.users.username,
      requestorUsername: req.users.username,
      requestorDepartment: req.users.departments?.name || 'Chung',
      requestedAction:
        (req.access_request_permissions[0]?.permission as 'VIEW' | 'DOWNLOAD') || 'VIEW',
      justification: req.reason,
      status: req.status,
      createdAt: req.submitted_at.toISOString(),
      requestedFrom: req.requested_from.toISOString(),
      requestedUntil: req.requested_until.toISOString(),
      decidedAt: req.access_request_decisions?.decided_at?.toISOString() ?? null,
      decisionNote: req.access_request_decisions?.decision_note ?? null,
    }));

    return { data, total };
  }

  /**
   * UC14: Reader cancels their pending access request.
   */
  async cancelRequest(
    id: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ id: string; status: string }> {
    const now = new Date();
    const request = await this.database.accessRequest.findUnique({
      where: { id },
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
          details: {
            requesterId: principal.userId.toString(),
          },
        },
        principal,
        context,
        tx,
      );
    });

    return { id, status: 'CANCELLED' };
  }

  /**
   * UC16: Owner approves or rejects an access request.
   */
  async decideRequest(
    id: string,
    input: DecideAccessRequestInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ id: string; status: string; grantId?: string }> {
    const executeDecision = async () => {
      const now = new Date();
      const request = await this.database.accessRequest.findUnique({
        where: { id },
        include: {
          documents: true,
          access_request_permissions: true,
        },
      });

      if (!request) {
        throw new NotFoundException({
          errorCode: AppErrorCode.ACCESS_REQUEST_NOT_FOUND,
          message: 'Access request was not found.',
        });
      }

      if (request.documents.owner_id !== principal.userId) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message: 'Only the document owner can decide access requests.',
        });
      }

      if (request.status !== 'PENDING') {
        throw new BadRequestException({
          errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
          message: `Cannot decide request in ${request.status} status.`,
        });
      }

      if (input.decision === 'REJECTED') {
        await this.database.$transaction(async (tx) => {
          await tx.accessRequest.update({
            where: { id },
            data: {
              status: 'REJECTED',
              updated_at: now,
              version: { increment: 1 },
            },
          });

          await tx.accessRequestDecision.create({
            data: {
              access_request_id: id,
              decision: 'REJECTED',
              decided_by: principal.userId,
              decision_note: input.decisionNote?.trim() ?? null,
              decided_at: now,
            },
          });

          await this.audit.record(
            {
              action: 'ACCESS_REQUEST_REJECTED',
              outcome: 'SUCCESS',
              objectId: id,
              documentId: request.document_id,
              details: {
                decidedBy: principal.userId.toString(),
                decisionNote: input.decisionNote?.trim() ?? null,
              },
            },
            principal,
            context,
            tx,
          );
        });

        return { id, status: 'REJECTED' };
      }

      // APPROVED: create grant
      const validUntil = new Date(now.getTime() + input.validDays * 86400000);
      const permissions =
        input.permissions && input.permissions.length > 0
          ? input.permissions
          : [request.access_request_permissions[0]?.permission || 'VIEW'];

      const grant = await this.grantsService.createGrant(
        {
          documentId: request.document_id,
          principalType: 'USER',
          principalUserId: request.requester_id,
          permissions: permissions as ('VIEW' | 'DOWNLOAD')[],
          validFrom: now.toISOString(),
          validUntil: validUntil.toISOString(),
          accessRequestId: id,
        },
        principal,
        context,
      );

      await this.audit.record(
        {
          action: 'ACCESS_REQUEST_APPROVED',
          outcome: 'SUCCESS',
          objectId: id,
          documentId: request.document_id,
          details: {
            decidedBy: principal.userId.toString(),
            grantId: grant.id,
            validDays: input.validDays,
            permissions: permissions.join(','),
          },
        },
        principal,
        context,
      );

      return { id, status: 'APPROVED', grantId: grant.id };
    };

    if (this.redlock) {
      return await this.redlock.withLock(`access-request:decision:${id}`, 5000, executeDecision);
    } else {
      return await executeDecision();
    }
  }
}
