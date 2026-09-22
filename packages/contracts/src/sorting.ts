import { z } from 'zod';

export const SortDirectionSchema = z.enum(['ASC', 'DESC']);
export type SortDirection = z.infer<typeof SortDirectionSchema>;

export const SortQuerySchema = z
  .object({
    sortBy: z.string().min(1).max(50).default('created_at'),
    sortOrder: SortDirectionSchema.default('DESC'),
  })
  .strict();

export type SortQuery = z.infer<typeof SortQuerySchema>;
