/**
 * @module AccessSessionsService
 * Thuật toán: Theo dõi phiên đọc tài liệu có giới hạn trần + phân lập phạm vi phòng ban (`scope_department_id`)
 * và chấm dứt phiên nguyên tử chống tranh chấp TOCTOU bằng cập nhật có điều kiện `updateMany(status = 'ACTIVE')` trong giao dịch.
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient, type Prisma, type session_status } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import {
  buildAccessSessionPrismaSearchOr,
  normalizeSessionSearchTerm,
  queryAccessSessionsWithSearch,
} from './access-sessions-search.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const SESSION_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AccessSessionDto {
  id: string;
  accessGrantId: string;
  documentVersionId: string;
  userId: string;
  username: string;
  fullName: string;
  documentId: string;
  documentCode: string;
  documentTitle: string;
  versionNo: number;
  ipAddress: string;
  userAgent: string | null;
  status: string;
  startedAt: string;
  lastActivityAt: string;
  endedAt: string | null;
  terminatedReason: string | null;
}

@Injectable()
export class AccessSessionsService {
  private readonly logger = new Logger(AccessSessionsService.name);
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
    @Optional() private readonly authorization?: AuthorizationService,
    @Optional() private readonly realtime?: RealtimeEventsService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Truy Vấn Phiên Truy Cập Có Giới Hạn Trần, Đếm Tổng & Đang Hoạt Động Kèm Cô Lập Cây Con Phòng Ban (`Scope-Isolated Bounded Session Listing`).
   */
  async listSessions(
    options?: {
      status?: session_status | 'ALL' | undefined;
      search?: string | undefined;
      limit?: number | undefined;
      page?: number | undefined;
    },
    actor?: AuthPrincipal,
  ): Promise<{
    data: AccessSessionDto[];
    total: number;
    activeCount: number;
    meta: {
      page: number;
      pageSize: number;
      total: number;
      totalPages: number;
      hasMore: boolean;
    };
  }> {
    const requestedStatus = options?.status ?? 'ACTIVE';
    const limit = Math.min(Math.max(options?.limit ?? 50, 1), 200);
    const page = Math.max(options?.page ?? 1, 1);
    const skip = (page - 1) * limit;

    let visibleDepts: bigint[] | null = null;
    const scopeWhere: Prisma.AccessSessionWhereInput = {};
    if (
      this.authorization &&
      actor &&
      typeof this.authorization.visibleDepartmentIds === 'function'
    ) {
      visibleDepts = await this.authorization.visibleDepartmentIds(
        actor,
        'ACCESS_SESSION',
        'TERMINATE',
      );
      if (visibleDepts !== null) {
        scopeWhere.document_versions = {
          document: { department_id: { in: visibleDepts } },
        };
      }
    }

    const trimmedSearch = normalizeSessionSearchTerm(options?.search);
    const hasCount = typeof this.database.accessSession?.count === 'function';

    let data: AccessSessionDto[];
    let filteredTotal: number | null;
    let totalAllCount: number | null;
    let activeTotalCount: number | null;

    if (trimmedSearch.length > 0 && typeof this.database?.$queryRaw === 'function') {
      const [searchResult, allCount, activeCountResult] = await Promise.all([
        queryAccessSessionsWithSearch({
          database: this.database,
          requestedStatus,
          term: trimmedSearch,
          visibleDepts,
          limit,
          skip,
        }),
        hasCount
          ? this.database.accessSession.count({ where: scopeWhere })
          : Promise.resolve<number | null>(null),
        hasCount
          ? this.database.accessSession.count({ where: { ...scopeWhere, status: 'ACTIVE' } })
          : Promise.resolve<number | null>(null),
      ]);
      data = searchResult.data;
      filteredTotal = searchResult.filteredTotal;
      totalAllCount = allCount;
      activeTotalCount = activeCountResult;
    } else {
      const where: Prisma.AccessSessionWhereInput = { ...scopeWhere };
      if (requestedStatus !== 'ALL') {
        where.status = requestedStatus;
      }
      if (trimmedSearch.length > 0) {
        where.OR = buildAccessSessionPrismaSearchOr(trimmedSearch);
      }

      const [sessions, filteredCount, allCount, activeCountResult] = await Promise.all([
        this.database.accessSession.findMany({
          where,
          take: limit,
          ...(skip > 0 ? { skip } : {}),
          orderBy: { started_at: 'desc' },
          include: {
            users: { select: { id: true, username: true, full_name: true } },
            document_versions: {
              select: {
                id: true,
                version_no: true,
                document: { select: { id: true, document_code: true, title: true } },
              },
            },
          },
        }),
        hasCount
          ? this.database.accessSession.count({ where })
          : Promise.resolve<number | null>(null),
        hasCount
          ? this.database.accessSession.count({ where: scopeWhere })
          : Promise.resolve<number | null>(null),
        hasCount
          ? this.database.accessSession.count({ where: { ...scopeWhere, status: 'ACTIVE' } })
          : Promise.resolve<number | null>(null),
      ]);

      data = sessions.map((s) => ({
        id: s.id,
        accessGrantId: s.access_grant_id,
        documentVersionId: s.document_version_id.toString(),
        userId: s.user_id.toString(),
        username: s.users.username,
        fullName: s.users.full_name,
        documentId: s.document_versions.document.id,
        documentCode: s.document_versions.document.document_code,
        documentTitle: s.document_versions.document.title,
        versionNo: s.document_versions.version_no,
        ipAddress: s.ip_address,
        userAgent: s.user_agent,
        status: s.status,
        startedAt: s.started_at.toISOString(),
        lastActivityAt: s.last_activity_at.toISOString(),
        endedAt: s.ended_at?.toISOString() ?? null,
        terminatedReason: s.terminated_reason,
      }));
      filteredTotal = filteredCount;
      totalAllCount = allCount;
      activeTotalCount = activeCountResult;
    }

    const matchedTotal = filteredTotal ?? data.length;
    const total = totalAllCount ?? matchedTotal;
    const activeCount = activeTotalCount ?? data.filter((item) => item.status === 'ACTIVE').length;
    const totalPages = Math.max(1, Math.ceil(matchedTotal / limit));

    return {
      data,
      total,
      activeCount,
      meta: {
        page,
        pageSize: limit,
        total: matchedTotal,
        totalPages,
        hasMore: page * limit < matchedTotal,
      },
    };
  }

  /**
   * Thuật toán: Chấm Dứt Phiên Truy Cập Nguyên Tử Chống TOCTOU Có Kiểm Chứng Phạm Vi Phòng Ban (`Conditional CAS Session Termination`).
   * Thực thi `updateMany({ where: { id, status: 'ACTIVE' } })` bên trong giao dịch; ném `409 Conflict` nếu `count === 0`.
   */
  async terminateSession(
    id: string,
    reason = 'Terminated by security officer',
    actor?: AuthPrincipal,
    context?: Partial<RequestContext>,
  ): Promise<{ id: string; status: string }> {
    if (!SESSION_UUID_REGEX.test(id)) {
      throw new BadRequestException('Session identifier must be a valid UUID.');
    }

    let visibleDepts: bigint[] | null = null;
    if (
      this.authorization &&
      actor &&
      typeof this.authorization.visibleDepartmentIds === 'function'
    ) {
      visibleDepts = await this.authorization.visibleDepartmentIds(
        actor,
        'ACCESS_SESSION',
        'TERMINATE',
      );
    }

    const executeInTx = async (tx: PrismaClient | Prisma.TransactionClient) => {
      const session = await tx.accessSession.findUnique({
        where: { id },
        include: {
          document_versions: {
            select: {
              document_id: true,
              document: { select: { department_id: true } },
            },
          },
        },
      });

      if (!session) {
        throw new NotFoundException(`Session ${id} not found.`);
      }

      const sessionMeta = session as {
        id: string;
        status: string;
        user_id?: bigint | null;
        document_versions?: {
          document_id?: string | null;
          document?: { department_id?: bigint | null } | null;
        } | null;
      };

      if (visibleDepts !== null) {
        const targetDeptId = sessionMeta.document_versions?.document?.department_id ?? null;
        if (targetDeptId === null || !visibleDepts.includes(targetDeptId)) {
          throw new ForbiddenException(
            'Cannot terminate access session outside your assigned department scope.',
          );
        }
      }

      const now = new Date();
      if (typeof tx.accessSession.updateMany === 'function') {
        const updated = await tx.accessSession.updateMany({
          where: { id, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: reason,
          },
        });
        if (updated.count === 0) {
          throw new ConflictException(`Session ${id} is no longer active.`);
        }
      } else {
        if (sessionMeta.status !== 'ACTIVE') {
          throw new ConflictException(`Session ${id} is no longer active.`);
        }
        await tx.accessSession.update({
          where: { id },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: reason,
          },
        });
      }

      if (this.auditWriter) {
        await this.auditWriter.writeLog(
          {
            action: 'ACCESS_SESSION_TERMINATED',
            outcome: 'SUCCESS',
            objectType: 'ACCESS_SESSION',
            objectId: id,
            accessSessionId: id,
            documentId: sessionMeta.document_versions?.document_id ?? null,
            actorUserId: actor?.userId ?? null,
            actorUsername: actor?.username ?? 'system',
            reasonCode: 'MANUAL_TERMINATION',
            chainPartition: 'SECURITY',
            details: {
              reason,
              targetUserId:
                sessionMeta.user_id !== undefined && sessionMeta.user_id !== null
                  ? sessionMeta.user_id.toString()
                  : null,
            },
          },
          context,
          typeof this.database?.$transaction === 'function'
            ? (tx as Prisma.TransactionClient)
            : undefined,
        );
      }

      return {
        id,
        status: 'TERMINATED',
        targetUserId:
          sessionMeta.user_id !== undefined && sessionMeta.user_id !== null
            ? sessionMeta.user_id.toString()
            : null,
        documentId: sessionMeta.document_versions?.document_id ?? null,
        departmentId:
          sessionMeta.document_versions?.document?.department_id !== undefined &&
          sessionMeta.document_versions?.document?.department_id !== null
            ? sessionMeta.document_versions.document.department_id.toString()
            : null,
      };
    };

    const txResult =
      typeof this.database?.$transaction === 'function'
        ? await this.database.$transaction((tx) => executeInTx(tx))
        : await executeInTx(this.database);

    this.logger.warn(`Access session ${id} terminated manually. Reason: ${reason}`);
    // CONFLICT-RESOLVED: Phát đồng thời sự kiện ACCESS_SESSION_UPDATED tới cả SOC và chủ phiên để trình xem tài liệu đóng tức thì khi bị ngắt phiên (V-05, BUG-063).
    this.realtime?.publish({
      type: 'ACCESS_SESSION_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId: txResult.departmentId,
      ...(txResult.targetUserId ? { targetUserIds: [txResult.targetUserId] } : {}),
      payload: {
        id: txResult.id,
        sessionId: txResult.id,
        documentId: txResult.documentId,
        status: txResult.status,
        action: 'TERMINATED',
        reason,
      },
    });
    return { id: txResult.id, status: txResult.status };
  }

  /**
   * Thuật toán: Đóng Sạch Phiên Đọc Của Chính Người Dùng Khi Đóng Hộp Thoại Xem Tài Liệu (`endOwnSession`).
   * Mục đích: Ngăn phiên `ACTIVE` tồn đọng trên bảng giám sát SOC sau khi người xem đã nhấn Đóng (V-10), chỉ cho phép chủ sở hữu phiên tự kết thúc (`user_id = principal.userId`, trạng thái `ENDED`).
   */
  async endOwnSession(
    id: string,
    principal: AuthPrincipal,
    context?: Partial<RequestContext>,
  ): Promise<{ id: string; status: string }> {
    if (!SESSION_UUID_REGEX.test(id)) {
      throw new BadRequestException('Session identifier must be a valid UUID.');
    }

    const session = await this.database.accessSession.findUnique({
      where: { id },
      select: {
        id: true,
        user_id: true,
        status: true,
        document_versions: {
          select: {
            document_id: true,
            document: { select: { department_id: true } },
          },
        },
      },
    });

    if (!session || session.user_id !== principal.userId) {
      throw new NotFoundException(`Session ${id} not found.`);
    }

    if (session.status !== 'ACTIVE') {
      return { id, status: session.status };
    }

    const now = new Date();
    if (typeof this.database.accessSession.updateMany === 'function') {
      const updated = await this.database.accessSession.updateMany({
        where: { id, user_id: principal.userId, status: 'ACTIVE' },
        data: {
          status: 'ENDED',
          ended_at: now,
          last_activity_at: now,
          terminated_reason: 'Closed by reader',
        },
      });
      if (updated.count === 0) {
        const latest = await this.database.accessSession.findUnique({
          where: { id },
          select: { status: true },
        });
        return { id, status: latest?.status ?? 'TERMINATED' };
      }
    } else {
      await this.database.accessSession.update({
        where: { id },
        data: {
          status: 'ENDED',
          ended_at: now,
          last_activity_at: now,
          terminated_reason: 'Closed by reader',
        },
      });
    }

    if (this.auditWriter) {
      await this.auditWriter
        .writeLog(
          {
            action: 'ACCESS_SESSION_ENDED',
            outcome: 'SUCCESS',
            objectType: 'ACCESS_SESSION',
            objectId: id,
            accessSessionId: id,
            documentId: session.document_versions?.document_id ?? null,
            actorUserId: principal.userId,
            actorUsername: principal.username,
            chainPartition: 'SECURITY',
            details: { reason: 'Closed by user' },
          },
          context,
        )
        .catch(() => undefined);
    }

    const ownSessionDeptId = (
      session.document_versions as {
        document?: { department_id?: bigint | null } | null;
      } | null
    )?.document?.department_id;
    this.realtime?.publish({
      type: 'ACCESS_SESSION_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId: ownSessionDeptId != null ? ownSessionDeptId.toString() : null,
      payload: {
        id,
        sessionId: id,
        documentId: session.document_versions?.document_id ?? null,
        status: 'ENDED',
        action: 'ENDED',
      },
    });

    return { id, status: 'ENDED' };
  }
}
