import { z } from 'zod';

// CONFLICT-RESOLVED: Đồng bộ thang bậc độ mật Bell-LaPadula theo chuẩn CSDL trong seed-catalog.ts và 01_supabase_full_schema_and_seed.sql (INTERNAL: 1 .. TOP_SECRET: 4), đồng thời đặt UNCLASSIFIED: 0 làm mức dự phòng (thỏa mãn CHECK rank >= 0) để triệt tiêu độ lệch +1 toàn hệ thống.
export const ClassificationRank = {
  UNCLASSIFIED: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
  TOP_SECRET: 4,
} as const;

export type ClassificationRank = (typeof ClassificationRank)[keyof typeof ClassificationRank];

/**
 * Algorithm: Deterministic Bell-LaPadula Lattice Rank Lookup.
 * Normalizes an arbitrary classification code (trim + uppercase, mapping legacy `RESTRICTED`
 * alias to `INTERNAL`) and resolves its monotonic security rank in O(1) dictionary lookup.
 */
export function resolveClassificationRank(code: string): ClassificationRank | null {
  const normalized = code.trim().toUpperCase();
  if (normalized === 'RESTRICTED') {
    return ClassificationRank.INTERNAL;
  }
  if (Object.hasOwn(ClassificationRank, normalized)) {
    return ClassificationRank[normalized as keyof typeof ClassificationRank];
  }
  return null;
}

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
