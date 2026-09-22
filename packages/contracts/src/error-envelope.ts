import { z } from 'zod';

export const ErrorEnvelopeSchema = z
  .object({
    statusCode: z.number().int().min(400).max(599),
    errorCode: z.string().min(1),
    message: z.string().min(1),
    correlationId: z.string().uuid(),
    timestamp: z.string().datetime(),
    details: z.unknown().optional(),
  })
  .strict();

export type ErrorEnvelope = z.infer<typeof ErrorEnvelopeSchema>;
