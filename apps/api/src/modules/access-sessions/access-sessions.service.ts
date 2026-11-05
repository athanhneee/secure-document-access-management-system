/**
 * Module: Quản lý Vòng đời Phiên Truy cập Tài liệu (Document Access Session Lifecycle Service)
 * Algorithm / Thuật toán: Theo dõi phiên đọc tài liệu đang hoạt động (Bounded Session Listing)
 *   và thực thi chấm dứt phiên đơn lẻ lũy đẳng (Idempotent Session Termination).
 */
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient, type session_status } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

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
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Algorithm / Thuật toán: Truy Vấn Phiên Truy Cập Có Giới Hạn Trần (Bounded Session Listing)
   * Mục đích: Trả về danh sách các phiên truy cập mới nhất theo trạng thái để giám sát vận hành an ninh.
   * Cơ chế hoạt động:
   *   - Kẹp ngưỡng kích thước trang tối đa ở 100 bản ghi (`Math.min(limit, 100)`), mặc định lọc `ACTIVE`
   *     và sắp xếp giảm dần theo `started_at` kèm thông tin người dùng và phiên bản tài liệu.
   */
  async listSessions(options?: {
    status?: session_status;
    limit?: number;
  }): Promise<{ data: AccessSessionDto[] }> {
    const status = options?.status ?? 'ACTIVE';
    const limit = Math.min(options?.limit ?? 50, 100);

    const where: { status?: session_status } = {};
    if (status) {
      where.status = status;
    }

    const sessions = await this.database.accessSession.findMany({
      where,
      take: limit,
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
    });

    const data: AccessSessionDto[] = sessions.map((s) => ({
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

    return { data };
  }

  /**
   * Algorithm / Thuật toán: Chấm Dứt Phiên Truy Cập Đơn Lẻ Lũy Đẳng (Idempotent Session Termination)
   * Mục đích: Ngắt ngay lập tức một phiên xem tài liệu cụ thể theo yêu cầu cưỡng chế của cán bộ an ninh.
   * Cơ chế hoạt động:
   *   - Kiểm tra sự tồn tại của phiên; nếu phiên không còn ở trạng thái `ACTIVE` thì trả về nguyên trạng (lũy đẳng).
   *   - Chuyển trạng thái sang `TERMINATED`, đóng dấu thời gian `ended_at` và lưu lý do chấm dứt.
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

    const session = await this.database.accessSession.findUnique({
      where: { id },
      include: {
        document_versions: {
          select: { document_id: true },
        },
      },
    });

    if (!session) {
      throw new NotFoundException(`Session ${id} not found.`);
    }

    if (session.status !== 'ACTIVE') {
      return { id: session.id, status: session.status };
    }

    const updated = await this.database.accessSession.update({
      where: { id },
      data: {
        status: 'TERMINATED',
        ended_at: new Date(),
        terminated_reason: reason,
      },
    });

    if (this.auditWriter) {
      const sessionMeta = session as {
        user_id?: bigint | null;
        document_versions?: { document_id?: string | null } | null;
      };
      await this.auditWriter.writeLog(
        {
          action: 'ACCESS_SESSION_TERMINATED',
          outcome: 'SUCCESS',
          objectType: 'ACCESS_SESSION',
          objectId: updated.id,
          accessSessionId: updated.id,
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
      );
    }

    this.logger.warn(`Access session ${id} terminated manually. Reason: ${reason}`);

    return { id: updated.id, status: updated.status };
  }
}
