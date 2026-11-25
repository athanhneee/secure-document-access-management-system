import { z } from 'zod';
import { PositiveBigIntSchema } from './validation-primitives.js';

const GrantPermissionSchema = z.enum(['VIEW', 'DOWNLOAD']);

/**
 * Thuật toán: Kiểm định loại trừ tương hỗ chủ thể (XOR Principal Discriminator) & thứ tự khoảng thời gian hiệu lực (`superRefine`).
 * Bắt buộc khai báo duy nhất `principalUserId` (khi `USER`) hoặc `principalRoleId` (khi `ROLE`), chặn tràn 64-bit `BIGINT` và đảm bảo `validUntil > validFrom`.
 */
export const CreateAccessGrantSchema = z
  .object({
    documentId: z.string().uuid(),
    principalType: z.enum(['USER', 'ROLE']),
    principalUserId: PositiveBigIntSchema.optional(),
    principalRoleId: PositiveBigIntSchema.optional(),
    permissions: z.array(GrantPermissionSchema).min(1).max(2),
    validFrom: z.string().datetime({ offset: true }),
    validUntil: z.string().datetime({ offset: true }),
    accessRequestId: z.string().uuid().optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.principalType === 'USER') {
      if (!data.principalUserId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['principalUserId'],
          message: 'principalUserId is required when principalType is USER.',
        });
      }
      if (data.principalRoleId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['principalRoleId'],
          message: 'principalRoleId must not be provided when principalType is USER.',
        });
      }
    } else if (data.principalType === 'ROLE') {
      if (!data.principalRoleId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['principalRoleId'],
          message: 'principalRoleId is required when principalType is ROLE.',
        });
      }
      if (data.principalUserId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['principalUserId'],
          message: 'principalUserId must not be provided when principalType is ROLE.',
        });
      }
    }
    const from = new Date(data.validFrom);
    const until = new Date(data.validUntil);
    if (until <= from) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['validUntil'],
        message: 'validUntil must be after validFrom.',
      });
    }
  });

export type CreateAccessGrantInput = z.infer<typeof CreateAccessGrantSchema>;

export const RevokeAccessGrantSchema = z
  .object({
    reason: z.string().trim().min(10, 'Revocation reason must be at least 10 characters.').max(500),
    expectedVersion: z.number().int().nonnegative().optional(),
  })
  .strict();

export type RevokeAccessGrantInput = z.infer<typeof RevokeAccessGrantSchema>;

export const ListAccessGrantsSchema = z
  .object({
    documentId: z.string().uuid().optional(),
    scope: z.enum(['all', 'owned', 'received']).default('all'),
    status: z.enum(['ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED']).optional(),
    principalType: z.enum(['USER', 'ROLE']).optional(),
    sort: z.enum(['granted_at', 'valid_until', 'status']).default('granted_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type ListAccessGrantsInput = z.infer<typeof ListAccessGrantsSchema>;

export const CreateAccessRequestSchema = z
  .object({
    documentId: z.string().uuid(),
    requestedAction: z.enum(['VIEW', 'DOWNLOAD']).default('VIEW'),
    reason: z.string().trim().min(10, 'Reason must be at least 10 characters.').max(1000),
    requestedFrom: z.string().datetime({ offset: true }).optional(),
    requestedUntil: z.string().datetime({ offset: true }).optional(),
  })
  .strict();

export type CreateAccessRequestInput = z.infer<typeof CreateAccessRequestSchema>;

export const DecideAccessRequestSchema = z
  .object({
    decision: z.enum(['APPROVED', 'REJECTED']),
    decisionNote: z.string().trim().max(1000).optional(),
    validDays: z.coerce.number().int().min(1).max(365).optional(),
    permissions: z
      .array(z.enum(['VIEW', 'DOWNLOAD']))
      .min(1)
      .max(2)
      .optional(),
  })
  .strict();

export type DecideAccessRequestInput = z.infer<typeof DecideAccessRequestSchema>;

export const ListAccessRequestsSchema = z
  .object({
    scope: z.enum(['my', 'incoming', 'all']).default('my'),
    status: z.enum(['PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type ListAccessRequestsInput = z.infer<typeof ListAccessRequestsSchema>;

export const CreateAccessSessionSchema = z
  .object({
    action: z.enum(['VIEW', 'DOWNLOAD']),
    grantId: z.string().uuid().optional(),
    deviceFingerprint: z.string().max(255).optional(),
  })
  .strict();

export type CreateAccessSessionInput = z.infer<typeof CreateAccessSessionSchema>;

export const PreviewPageParamSchema = z
  .object({
    pageNumber: z.coerce.number().int().min(1),
  })
  .strict();

export const DownloadTicketParamSchema = z
  .object({
    ticket: z.string().regex(/^DT-[0-9a-f]{64}$/i, 'Invalid download ticket format'),
  })
  .strict();

export const WatermarkTokenParamSchema = z
  .object({
    token: z.string().regex(/^WM-[0-9a-f]{12,64}$/i, 'Invalid watermark token format'),
  })
  .strict();

export const ListAccessSessionsSchema = z
  .object({
    // CONFLICT-RESOLVED: Đồng bộ miền trạng thái phiên đọc với Prisma enum session_status (ACTIVE | ENDED | TERMINATED) và bổ sung ALL để xem lịch sử (#20).
    status: z.enum(['ALL', 'ACTIVE', 'ENDED', 'TERMINATED']).optional(),
    search: z.string().trim().max(120).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    page: z.coerce.number().int().min(1).default(1),
  })
  .strict();

export const TerminateAccessSessionSchema = z
  .object({
    reason: z
      .string()
      .trim()
      .min(5, 'Termination reason must be at least 5 characters.')
      .max(500)
      .optional(),
  })
  .strict();
