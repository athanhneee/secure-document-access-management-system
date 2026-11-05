/**
 * Module: Documents HTTP Controller Validation & Binary Reply Helpers
 * Algorithm: Validates UUID/Zod request payloads, extracts principal & request context, sanitizes
 *   `Content-Disposition` filenames against HTTP header injection, and writes `no-store` binary replies.
 */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { DownloadTicketParamSchema, UuidParamSchema } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { DeliveryFileResult } from './document-delivery.service.js';

interface SafeParseSchema<T> {
  safeParse(
    data: unknown,
  ): { success: true; data: T } | { success: false; error: { flatten: () => unknown } };
}

/**
 * Algorithm: Strict UUID Route Parameter Parser
 * Validates `{ id }` route params via `UuidParamSchema` and throws `BadRequestException` on mismatch.
 */
export function parseDocumentUuid(params: unknown): string {
  const parsed = UuidParamSchema.safeParse(params);
  if (!parsed.success) throw new BadRequestException('Invalid document UUID.');
  return parsed.data.id;
}

/**
 * Algorithm: Preview Page Route Parameter Parser
 * Extracts validated document UUID and 1-based positive `pageNumber` from route params.
 */
export function parsePreviewPageParams(params: unknown): { id: string; pageNum: number } {
  const raw = params as Record<string, string>;
  const pageNum = Number(raw['pageNumber']);
  if (Number.isNaN(pageNum) || pageNum < 1) throw new BadRequestException('Invalid page number.');
  return { id: parseDocumentUuid({ id: raw['id'] }), pageNum };
}

/**
 * Algorithm: Download Ticket Route Parameter Parser
 * Validates `DT-<hex>` ticket parameter via `DownloadTicketParamSchema`.
 */
export function parseDownloadTicketParam(params: unknown): string {
  const parsed = DownloadTicketParamSchema.safeParse(params);
  if (!parsed.success) throw new BadRequestException('Invalid ticket format.');
  return parsed.data.ticket;
}

/**
 * Algorithm: Zod Request Payload Validator
 * Parses query/body input against a Zod schema and surfaces flattened field errors on failure.
 */
export function parseBodyOrQuery<T>(schema: SafeParseSchema<T>, payload: unknown): T {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
  return parsed.data;
}

/**
 * Algorithm: Access Session Identifier Extractor
 * Resolves session ID from query string or `X-Access-Session-Id` request header.
 */
export function resolveAccessSessionId(
  sessionId: string | undefined,
  request: FastifyRequest,
): string {
  const sid = sessionId || (request.headers['x-access-session-id'] as string);
  if (!sid) {
    throw new BadRequestException(
      'sessionId query parameter or X-Access-Session-Id header is required.',
    );
  }
  return sid;
}

/**
 * Algorithm: HTTP `Content-Disposition` Filename Sanitizer
 * Replaces CR/LF, quotes, backslashes, and non-printable ASCII bytes (`0x20..0x7E`) with `_`.
 */
export function sanitizeHeaderFilename(filename: string): string {
  return filename.replace(/["\r\n\\]/g, '_').replace(/[^\x20-\x7E]/g, '_');
}

/**
 * Algorithm: No-Store Inline PDF Preview Response Writer
 * Emits strict anti-cache headers, total page metadata, and sanitized inline `Content-Disposition`.
 */
export function sendInlinePreviewReply(reply: FastifyReply, result: DeliveryFileResult): void {
  const safeFilename = sanitizeHeaderFilename(result.filename);
  reply
    .type(result.mimeType)
    .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
    .header('Pragma', 'no-cache')
    .header('X-Total-Pages', (result.totalPages ?? 1).toString())
    .header('Access-Control-Expose-Headers', 'X-Total-Pages, Content-Disposition')
    .header('Content-Disposition', `inline; filename="${safeFilename}"`)
    .send(result.buffer);
}

/**
 * Algorithm: No-Store Attachment Download Response Writer
 * Emits strict anti-cache headers and sanitized attachment `Content-Disposition`.
 */
export function sendAttachmentDownloadReply(reply: FastifyReply, result: DeliveryFileResult): void {
  const safeFilename = sanitizeHeaderFilename(result.filename);
  reply
    .type(result.mimeType)
    .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
    .header('Pragma', 'no-cache')
    .header('Content-Disposition', `attachment; filename="${safeFilename}"`)
    .send(result.buffer);
}

export function extractDocumentPrincipal(request: FastifyRequest): AuthPrincipal {
  if (!request.auth) throw new UnauthorizedException('Authentication required.');
  return request.auth;
}

export function extractDocumentRequestContext(request: FastifyRequest): RequestContext {
  return {
    ip: request.ip,
    ...(request.headers['user-agent'] ? { userAgent: request.headers['user-agent'] } : {}),
    correlationId: request.correlationId ?? randomUUID(),
  };
}
