import { z } from 'zod';

export const PermissionCodeSchema = z.enum(['DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE']);
export type PermissionCode = z.infer<typeof PermissionCodeSchema>;

export const PermissionActionSchema = z
  .object({
    resourceType: z.string().min(1).max(80),
    action: PermissionCodeSchema,
  })
  .strict();

export type PermissionAction = z.infer<typeof PermissionActionSchema>;
