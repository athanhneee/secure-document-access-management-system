import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type { ZodType } from 'zod';
import {
  PositiveBigIntSchema,
  UuidParamSchema,
  type UpdateDetectionRuleConfigInput,
} from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { CsrfService } from '../auth/csrf.service.js';
import type { DetectionRule } from './security-detection.service.js';

// CONFLICT-RESOLVED: Giới hạn actionId trong miền số nguyên dương 64-bit MAX_PG_BIGINT tránh lỗi tràn kiểu PostgreSQL (HIGH-12)
const ActionIdParamSchema = PositiveBigIntSchema;

/**
 * Algorithm: Strict Request Boundary Validation (UUID / Numeric BigInt / Zod DTO / CSRF+Auth).
 */
export function parseUuidParam(id: string, label: string): string {
  const parsed = UuidParamSchema.safeParse({ id });
  if (!parsed.success) {
    throw new BadRequestException(`Invalid ${label} UUID.`);
  }
  return parsed.data.id;
}

export function parseActionIdParam(actionId: string): bigint {
  const parsed = ActionIdParamSchema.safeParse(actionId);
  if (!parsed.success) {
    throw new BadRequestException('Invalid incident action ID.');
  }
  return parsed.data;
}

export function requireAuthenticatedPrincipal(req: FastifyRequest): AuthPrincipal {
  if (!req.auth) {
    throw new UnauthorizedException('Authentication required.');
  }
  return req.auth;
}

export function requireMutatingPrincipal(csrf: CsrfService, req: FastifyRequest): AuthPrincipal {
  csrf.assertRequest(req);
  return requireAuthenticatedPrincipal(req);
}

export function parseZodPayload<T>(schema: ZodType<T>, payload: unknown): T {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new BadRequestException(parsed.error.flatten());
  }
  return parsed.data;
}

export function toDetectionRulePatch(data: UpdateDetectionRuleConfigInput): Partial<DetectionRule> {
  const patch: Partial<DetectionRule> = {};
  if (data.isEnabled !== undefined) patch.isEnabled = data.isEnabled;
  if (data.severity !== undefined) patch.severity = data.severity;
  if (data.threshold !== undefined) patch.threshold = data.threshold;
  if (data.windowMinutes !== undefined) patch.windowMinutes = data.windowMinutes;
  if (data.cooldownMinutes !== undefined) patch.cooldownMinutes = data.cooldownMinutes;
  if (data.parameters !== undefined) patch.parameters = data.parameters;
  return patch;
}
