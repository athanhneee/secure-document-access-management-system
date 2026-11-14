/**
 * Module: Controlled Delivery Session Validation & Distributed Single-Use Download Ticket Helper
 * Thuật toán: Kiểm Định Phiên Phân Phối Zero-Trust & Phát Hành Vé Tải Một Lần Phân Tán (`DistributedStateService`).
 *   1. Kiểm chứng phiên hoạt động (`ACTIVE`), chủ sở hữu phiên, ràng buộc IP/User-Agent và nghĩa vụ ABAC thời gian thực.
 *   2. Sinh vé mật mã 256-bit (`DT-<64hex>`), chỉ lưu mã băm SHA-256 trên kho phân tán kèm TTL ngắn hạn (`failClosedInProd: true`).
 *   3. Tái xuất hàm tiêu thụ nguyên tử `consumeOnce` và tái xác minh CSDL tại thời điểm đổi vé từ `delivery-ticket-redemption.helper.ts`.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import crypto from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type { DocumentPepService } from './document-pep.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DOWNLOAD_TICKET_NAMESPACE = 'download-ticket';

const DELIVERY_SESSION_INCLUDE = {
  document_versions: {
    include: {
      document: {
        include: {
          classification_history: {
            where: { effective_to: null },
            include: { classification_levels: true, business_categories: true },
          },
        },
      },
    },
  },
} as const;

export interface DownloadTicketEntry {
  documentId: string;
  sessionId: string;
  userId: bigint;
  principal: AuthPrincipal;
  issuedIp: string | null;
  createdAt: number;
  expiresAt: number;
}

export interface DeliveryFileResult {
  buffer: Buffer;
  mimeType: string;
  filename: string;
  fileSizeBytes: number;
  outputSha256Hash: string;
  watermarkToken?: string | undefined;
  totalPages?: number | undefined;
}

/**
 * Thuật toán: Chuẩn hóa IP máy khách (loại bỏ tiền tố `::ffff:`) phục vụ đối sánh ràng buộc phiên và vé tải.
 */
export function normalizeDeliveryClientIp(ip: string | null | undefined): string | null {
  const trimmed = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
  if (!trimmed) return null;
  return trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
}

function hashDownloadTicket(ticket: string): string {
  return crypto.createHash('sha256').update(ticket, 'utf8').digest('hex');
}

function assertSessionContextBinding(
  session: { ip_address?: string | null; user_agent?: string | null },
  context: RequestContext,
): void {
  const boundIp = normalizeDeliveryClientIp(session.ip_address);
  const callerIp = normalizeDeliveryClientIp(context?.ip);
  if (boundIp && callerIp && boundIp !== callerIp) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Client IP address does not match the bound access session.',
    });
  }
  const boundUa = session.user_agent?.trim() || null;
  const callerUa = context?.userAgent?.trim() || null;
  if (boundUa && callerUa && boundUa !== callerUa) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Client User-Agent does not match the bound access session.',
    });
  }
}

/**
 * Thuật toán: Xác Minh Phiên Phân Phối Tài Liệu Zero-Trust (`loadValidatedDeliverySession`).
 */
export async function loadValidatedDeliverySession(params: {
  database: PrismaClient;
  pep: DocumentPepService;
  sessionId: string;
  documentId: string;
  principal: AuthPrincipal;
  context: RequestContext;
  now: Date;
  requireDownloadPolicy: boolean;
}) {
  const { database, pep, sessionId, documentId, principal, context, now, requireDownloadPolicy } =
    params;

  const session = await database.accessSession.findUnique({
    where: { id: sessionId },
    include: DELIVERY_SESSION_INCLUDE,
  });

  if (!session) {
    throw new NotFoundException({
      errorCode: AppErrorCode.SESSION_NOT_FOUND,
      message: 'Access session was not found.',
    });
  }
  if (session.status !== 'ACTIVE') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.SESSION_TERMINATED,
      message: `Session is no longer active (status: ${session.status}).`,
    });
  }
  if (session.user_id !== principal.userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.SESSION_USER_MISMATCH,
      message: 'Session does not belong to the calling user.',
    });
  }
  if (session.document_versions.document_id !== documentId) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Session is not associated with this document.',
    });
  }

  assertSessionContextBinding(
    session as { ip_address?: string | null; user_agent?: string | null },
    context,
  );

  if (typeof pep?.enforceSessionPolicy !== 'function') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Policy enforcement point is unavailable; failing closed.',
    });
  }
  await pep.enforceSessionPolicy(
    session,
    requireDownloadPolicy ? 'DOWNLOAD' : 'VIEW',
    principal,
    context,
    now,
  );

  return session;
}

/**
 * Thuật toán: Phát Hành Vé Tải Dùng Một Lần Phân Tán (`issueShortLivedDownloadTicket`).
 */
export async function issueShortLivedDownloadTicket(params: {
  database: PrismaClient;
  pep: DocumentPepService;
  grantsService: AccessGrantsService;
  stateStore: DistributedStateService;
  ticketTtlSeconds: number;
  documentId: string;
  sessionId: string;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<{ ticket: string; expiresAt: string; ttlSeconds: number }> {
  const {
    database,
    pep,
    grantsService,
    stateStore,
    ticketTtlSeconds,
    documentId,
    sessionId,
    principal,
    context,
  } = params;
  const nowDate = new Date();
  const now = nowDate.getTime();

  const session = await database.accessSession.findUnique({
    where: { id: sessionId },
    include: DELIVERY_SESSION_INCLUDE,
  });

  if (!session || session.status !== 'ACTIVE' || session.user_id !== principal.userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.SESSION_TERMINATED,
      message: 'Active session required to generate download ticket.',
    });
  }
  if (session.document_versions && session.document_versions.document_id !== documentId) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Session is not associated with this document.',
    });
  }

  if (typeof pep?.enforceSessionPolicy !== 'function') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Policy enforcement point is unavailable; failing closed.',
    });
  }
  await pep.enforceSessionPolicy(session, 'DOWNLOAD', principal, context, nowDate);

  const currentClassification = session.document_versions?.document?.classification_history?.[0];
  if (currentClassification?.classification_levels?.allow_download === false) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Document classification level does not allow downloads.',
    });
  }

  if (typeof grantsService?.assertGrantValidForAccess === 'function') {
    await grantsService.assertGrantValidForAccess(
      session.access_grant_id,
      principal.userId,
      'DOWNLOAD',
      nowDate,
      documentId,
    );
  }

  const ticket = `DT-${crypto.randomBytes(32).toString('hex')}`;
  const ttlMs = Math.max(1_000, ticketTtlSeconds * 1_000);
  const expiresAtMs = now + ttlMs;
  const rawPrincipal = principal as unknown as Record<string, unknown>;
  const payload = {
    documentId,
    sessionId,
    userId: principal.userId.toString(),
    principal: {
      ...rawPrincipal,
      userId: principal.userId.toString(),
      ...(rawPrincipal['departmentId'] !== undefined
        ? {
            departmentId:
              rawPrincipal['departmentId'] !== null ? String(rawPrincipal['departmentId']) : null,
          }
        : {}),
    },
    issuedIp: normalizeDeliveryClientIp(context?.ip),
    createdAt: now,
    expiresAt: expiresAtMs,
  };

  await stateStore.putEphemeral(
    DOWNLOAD_TICKET_NAMESPACE,
    hashDownloadTicket(ticket),
    payload,
    ttlMs,
    {
      failClosedInProd: true,
    },
  );

  return { ticket, expiresAt: new Date(expiresAtMs).toISOString(), ttlSeconds: ticketTtlSeconds };
}

export {
  consumeSingleUseDownloadTicket,
  reverifyRedeemedTicketState,
} from './delivery-ticket-redemption.helper.js';
