/**
 * Module: Single-Use Download Ticket Atomic Consumption & Real-Time DB Re-Verification Helper
 * Thuật toán: Tiêu Thụ Vé Tải Nguyên Tử & Tái Kiểm Định Trạng Thái Thực Thi Khi Đổi Vé (`consumeSingleUseDownloadTicket` & `reverifyRedeemedTicketState`).
 *   1. Tiêu thụ một lần băm SHA-256 của vé qua `DistributedStateService.consumeOnce` (`failClosedInProd: true`) để loại bỏ nguy cơ dùng lại vé giữa nhiều bản sao API.
 *   2. Tại đúng thời điểm đổi vé (`/download-with-ticket/:ticket`), truy vấn trực tiếp CSDL xác nhận `AccessSession.status === 'ACTIVE'`,
 *      `AccessGrant.status === 'ACTIVE'` và còn hạn `valid_until`, `User.status === 'ACTIVE'`, cùng ràng buộc địa chỉ IP máy khách.
 */
import { ForbiddenException } from '@nestjs/common';
import crypto from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { normalizeDeliveryClientIp, type DownloadTicketEntry } from './delivery-ticket.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DOWNLOAD_TICKET_NAMESPACE = 'download-ticket';

interface StoredDownloadTicketPayload {
  documentId: string;
  sessionId: string;
  userId: string;
  principal: Record<string, unknown> & { userId: string; departmentId?: string | null };
  issuedIp: string | null;
  createdAt: number;
  expiresAt: number;
}

/**
 * Thuật toán: Đọc-và-Xóa nguyên tử vé tải dùng một lần trên kho phân tán và khôi phục kiểu `BigInt` cho `AuthPrincipal`.
 */
export async function consumeSingleUseDownloadTicket(
  stateStore: DistributedStateService,
  ticket: string,
): Promise<DownloadTicketEntry> {
  const ticketHash = crypto.createHash('sha256').update(ticket, 'utf8').digest('hex');
  const stored = await stateStore.consumeOnce<StoredDownloadTicketPayload>(
    DOWNLOAD_TICKET_NAMESPACE,
    ticketHash,
    { failClosedInProd: true },
  );

  if (!stored) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_INVALID,
      message: 'Download ticket is invalid or has already been used.',
    });
  }

  if (Date.now() > stored.expiresAt) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_EXPIRED,
      message: 'Download ticket has expired.',
    });
  }

  const restoredPrincipal = {
    ...stored.principal,
    userId: BigInt(stored.principal.userId),
    ...(stored.principal.departmentId !== undefined
      ? {
          departmentId:
            stored.principal.departmentId !== null
              ? BigInt(stored.principal.departmentId)
              : undefined,
        }
      : {}),
  } as unknown as AuthPrincipal;

  return {
    documentId: stored.documentId,
    sessionId: stored.sessionId,
    userId: BigInt(stored.userId),
    principal: restoredPrincipal,
    issuedIp: stored.issuedIp ?? null,
    createdAt: stored.createdAt,
    expiresAt: stored.expiresAt,
  };
}

/**
 * Thuật toán: Tái Kiểm Định Trực Tiếp CSDL Tại Thời Điểm Tiêu Thụ Vé (`reverifyRedeemedTicketState`)
 * Ngăn chặn vé chưa hết hạn tiếp tục tải tài liệu khi phiên đã bị chấm dứt, quyền cấp phát bị thu hồi/quá hạn, tài khoản bị khóa hoặc khác IP.
 */
export async function reverifyRedeemedTicketState(params: {
  database: PrismaClient;
  grantsService: AccessGrantsService;
  entry: DownloadTicketEntry;
  context: RequestContext;
  now: Date;
}): Promise<void> {
  const { database, grantsService, entry, context, now } = params;

  if (typeof database?.accessSession?.findUnique === 'function') {
    const session = await database.accessSession.findUnique({
      where: { id: entry.sessionId },
    });
    if (!session || session.status !== 'ACTIVE' || session.user_id !== entry.userId) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.SESSION_TERMINATED,
        message: 'Access session associated with download ticket is no longer active.',
      });
    }

    const callerIp = normalizeDeliveryClientIp(context?.ip);
    const sessionIp = normalizeDeliveryClientIp(
      (session as { ip_address?: string | null }).ip_address,
    );
    const expectedIp = sessionIp ?? entry.issuedIp;
    if (callerIp && expectedIp && callerIp !== expectedIp) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Client IP does not match the access session bound to this download ticket.',
      });
    }

    if (typeof grantsService?.assertGrantValidForAccess === 'function') {
      await grantsService.assertGrantValidForAccess(
        session.access_grant_id,
        entry.userId,
        'DOWNLOAD',
        now,
        entry.documentId,
      );
    }

    if (session.access_grant_id && typeof database?.accessGrant?.findUnique === 'function') {
      const grant = await database.accessGrant.findUnique({
        where: { id: session.access_grant_id },
      });
      const validFromOk = !grant?.valid_from || new Date(grant.valid_from) <= now;
      const validUntilOk = !grant?.valid_until || new Date(grant.valid_until) > now;
      if (!grant || grant.status !== 'ACTIVE' || !validFromOk || !validUntilOk) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'Underlying access grant is no longer active or has expired.',
        });
      }
    }
  } else if (entry.issuedIp) {
    const callerIp = normalizeDeliveryClientIp(context?.ip);
    if (callerIp && callerIp !== entry.issuedIp) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Client IP does not match the issued download ticket.',
      });
    }
  }

  if (typeof database?.user?.findUnique === 'function') {
    const user = await database.user.findUnique({
      where: { id: entry.userId },
      select: { status: true },
    });
    if (!user || user.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'User account associated with download ticket is no longer active.',
      });
    }
  }
}
