import { z } from 'zod';

export const LivenessResponseSchema = z
  .object({
    status: z.literal('ok'),
  })
  .strict();

export type LivenessResponse = z.infer<typeof LivenessResponseSchema>;

export const DependencyHealthSchema = z
  .object({
    status: z.enum(['up', 'down']),
    latencyMs: z.number().int().min(0).optional(),
    message: z.string().optional(),
  })
  .strict();

export type DependencyHealth = z.infer<typeof DependencyHealthSchema>;

export const ReadinessResponseSchema = z
  .object({
    status: z.enum(['ready', 'degraded']),
    timestamp: z.string().datetime(),
    checks: z
      .object({
        database: DependencyHealthSchema,
        redis: DependencyHealthSchema,
        storage: DependencyHealthSchema,
      })
      .strict(),
  })
  .strict();

export type ReadinessResponse = z.infer<typeof ReadinessResponseSchema>;
