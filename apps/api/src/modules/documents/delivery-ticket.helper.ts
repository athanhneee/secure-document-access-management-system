/**
 * Module: Controlled Delivery Session Validation & Single-Use Download Ticket Helper
 * Algorithm: Validates active `AccessSession` ownership/document/policy bounds, issues lazy-pruned
 *   256-bit CSPRNG download tickets (`DT-<hex>`), and atomically consumes tickets prior to redemption.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import crypto from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { DocumentPepService } from './document-pep.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface DownloadTicketEntry {
  documentId: string;
  sessionId: string;
  userId: bigint;
  principal: AuthPrincipal;
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
 * Algorithm: Zero-Trust Delivery Session Verification
 * Loads `accessSession` with active classification metadata and verifies status, caller identity, document binding, and policy TTL.
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
    include: {
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
    },
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
 * Algorithm: Lazy-Pruned Short-Lived CSPRNG Download Ticket Issuance
 * Evicts expired tickets, verifies active `DOWNLOAD` session/classification/grant, and issues a 256-bit single-use token.
 */
export async function issueShortLivedDownloadTicket(params: {
  database: PrismaClient;
  pep: DocumentPepService;
  grantsService: AccessGrantsService;
  downloadTickets: Map<string, DownloadTicketEntry>;
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
    downloadTickets,
    ticketTtlSeconds,
    documentId,
    sessionId,
    principal,
    context,
  } = params;
  const nowDate = new Date();
  const now = nowDate.getTime();

  for (const [key, existing] of downloadTickets.entries()) {
    if (now > existing.expiresAt) {
      downloadTickets.delete(key);
    }
  }
  while (downloadTickets.size >= 10_000) {
    const oldestKey = downloadTickets.keys().next().value;
    if (!oldestKey) break;
    downloadTickets.delete(oldestKey);
  }

  const session = await database.accessSession.findUnique({
    where: { id: sessionId },
    include: {
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
    },
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
  const expiresAtMs = now + ticketTtlSeconds * 1000;
  downloadTickets.set(ticket, {
    documentId,
    sessionId,
    userId: principal.userId,
    principal,
    createdAt: now,
    expiresAt: expiresAtMs,
  });

  return {
    ticket,
    expiresAt: new Date(expiresAtMs).toISOString(),
    ttlSeconds: ticketTtlSeconds,
  };
}

/**
 * Algorithm: Atomic Single-Use Ticket Consumption
 * Deletes the ticket from memory immediately before checking wall-clock expiration to guarantee replay resistance.
 */
export function consumeSingleUseDownloadTicket(
  downloadTickets: Map<string, DownloadTicketEntry>,
  ticket: string,
): DownloadTicketEntry {
  const entry = downloadTickets.get(ticket);
  if (!entry) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_INVALID,
      message: 'Download ticket is invalid or has already been used.',
    });
  }

  downloadTickets.delete(ticket);

  if (Date.now() > entry.expiresAt) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOWNLOAD_TICKET_EXPIRED,
      message: 'Download ticket has expired.',
    });
  }

  return entry;
}
