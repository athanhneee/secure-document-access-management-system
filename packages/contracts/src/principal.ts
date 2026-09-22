import { z } from 'zod';

export const PrincipalTypeSchema = z.enum(['USER', 'ROLE']);
export type PrincipalType = z.infer<typeof PrincipalTypeSchema>;

export const UserPrincipalSchema = z
  .object({
    id: z.number().int().positive(),
    username: z.string().min(1).max(80),
    email: z.string().email(),
    departmentId: z.number().int().positive().nullable(),
    roles: z.array(z.string().min(1)),
    clearanceRank: z.number().int().min(0),
    attributes: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export type UserPrincipal = z.infer<typeof UserPrincipalSchema>;
