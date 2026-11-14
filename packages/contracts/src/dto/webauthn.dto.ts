import { z } from 'zod';

/**
 * Module: WebAuthn / FIDO2 Registration & Authentication DTO Schemas (`@sda/contracts`)
 * Thuật toán: Xác thực cấu trúc yêu cầu đăng ký và xác thực khóa phần cứng FIDO2/Passkey với chế độ `.strict()` chống tràn thuộc tính.
 */
export const WebAuthnRegistrationOptionsRequestSchema = z
  .object({
    label: z.string().trim().min(1).max(80).optional(),
  })
  .strict();

export const WebAuthnVerifyRegistrationRequestSchema = z
  .object({
    challengeToken: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
    label: z.string().trim().min(1).max(80).optional(),
  })
  .strict();

export const WebAuthnAuthOptionsRequestSchema = z
  .object({
    username: z.string().trim().min(1).max(255).optional(),
  })
  .strict();

export const WebAuthnVerifyAuthRequestSchema = z
  .object({
    challengeToken: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
  })
  .strict();
