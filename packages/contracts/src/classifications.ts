import { z } from 'zod';

export const ClassificationRank = {
  UNCLASSIFIED: 1,
  INTERNAL: 2,
  CONFIDENTIAL: 3,
  SECRET: 4,
  TOP_SECRET: 5,
} as const;

export type ClassificationRank = (typeof ClassificationRank)[keyof typeof ClassificationRank];

export const ClassificationLevelSchema = z
  .object({
    id: z.number().int().positive(),
    code: z.string().min(1).max(40),
    name: z.string().min(1).max(100),
    rank: z.number().int().min(0),
    description: z.string().nullable().optional(),
    defaultViewDays: z.number().int().positive().nullable().optional(),
    allowDownload: z.boolean(),
    requireWatermark: z.boolean(),
    isActive: z.boolean(),
  })
  .strict();

export type ClassificationLevelDto = z.infer<typeof ClassificationLevelSchema>;
