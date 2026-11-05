import { z } from 'zod';

export const WebAuthnRegistrationOptionsRequestSchema = z
  .object({
    label: z.string().trim().min(1).max(80).optional(),
  })
  .strict();

export type WebAuthnRegistrationOptionsRequest = z.infer<
  typeof WebAuthnRegistrationOptionsRequestSchema
>;

export const WebAuthnVerifyRegistrationRequestSchema = z
  .object({
    challengeToken: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
    label: z.string().trim().min(1).max(80).optional(),
  })
  .strict();

export type WebAuthnVerifyRegistrationRequest = z.infer<
  typeof WebAuthnVerifyRegistrationRequestSchema
>;

export const WebAuthnAuthOptionsRequestSchema = z
  .object({
    username: z.string().trim().min(1).max(255).optional(),
  })
  .strict();

export type WebAuthnAuthOptionsRequest = z.infer<typeof WebAuthnAuthOptionsRequestSchema>;

export const WebAuthnVerifyAuthRequestSchema = z
  .object({
    challengeToken: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
  })
  .strict();

export type WebAuthnVerifyAuthRequest = z.infer<typeof WebAuthnVerifyAuthRequestSchema>;
