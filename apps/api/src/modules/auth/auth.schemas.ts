/**
 * @module AuthSchemas
 * Algorithm: Strict Bounded Zod Input Validation Schemas for Authentication Endpoints.
 */
import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

export {
  WebAuthnAuthOptionsRequestSchema,
  WebAuthnRegistrationOptionsRequestSchema,
  WebAuthnVerifyAuthRequestSchema,
  WebAuthnVerifyRegistrationRequestSchema,
} from '@sda/contracts';

export const LoginSchema = z.object({
  identifier: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(128),
});

export const ForgotSchema = z.object({
  identifier: z.string().trim().min(1).max(255),
});

export const ResetSchema = z.object({
  token: z.string().min(40).max(100),
  newPassword: z.string().min(1).max(128),
});

export const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
});

export const EnrollmentSchema = z.object({
  label: z.string().trim().min(1).max(80).optional(),
});

export const TotpSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

export const MfaVerifySchema = z
  .object({
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    recoveryCode: z.string().min(16).max(64).optional(),
  })
  .refine((value) => Boolean(value.code || value.recoveryCode));

export const DisableMfaSchema = z
  .object({
    currentPassword: z.string().min(1).max(128),
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    recoveryCode: z.string().min(16).max(64).optional(),
  })
  .refine((value) => Boolean(value.code || value.recoveryCode));

/**
 * Algorithm / Thuật toán: Xác thực lược đồ đầu vào Zod an toàn không rò rỉ chi tiết nội bộ.
 */
export function parseAuthBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (!result.success) throw new BadRequestException('Request validation failed.');
  return result.data;
}
