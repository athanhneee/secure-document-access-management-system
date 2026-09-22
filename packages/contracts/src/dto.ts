import { z } from 'zod';

export const IdParamSchema = z
  .object({
    id: z.coerce.number().int().positive(),
  })
  .strict();

export type IdParam = z.infer<typeof IdParamSchema>;

export const UuidParamSchema = z
  .object({
    id: z.string().uuid(),
  })
  .strict();

export type UuidParam = z.infer<typeof UuidParamSchema>;
