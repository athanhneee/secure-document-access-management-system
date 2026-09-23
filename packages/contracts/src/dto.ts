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

export const DocumentStatusSchema = z.enum(['DRAFT', 'ACTIVE', 'ARCHIVED', 'DELETED']);
export type DocumentStatus = z.infer<typeof DocumentStatusSchema>;

export const ScanStatusSchema = z.enum(['PENDING', 'CLEAN', 'INFECTED', 'FAILED']);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

export const CreateDocumentDraftSchema = z
  .object({
    title: z.string().trim().min(1).max(255),
    departmentId: z.coerce.bigint().positive(),
    description: z.string().max(2000).optional(),
    documentCode: z.string().min(1).max(60).optional(),
    retentionUntil: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Retention date must be in YYYY-MM-DD format')
      .optional(),
    classificationLevelId: z.coerce.bigint().positive().optional(),
    businessCategoryId: z.coerce.bigint().positive().optional(),
    reason: z.string().max(500).optional(),
  })
  .strict();

export type CreateDocumentDraftInput = z.infer<typeof CreateDocumentDraftSchema>;

export const UpdateDocumentMetadataSchema = z
  .object({
    title: z.string().trim().min(1).max(255).optional(),
    description: z.string().max(2000).nullable().optional(),
    departmentId: z.coerce.bigint().positive().optional(),
    retentionUntil: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Retention date must be in YYYY-MM-DD format')
      .nullable()
      .optional(),
  })
  .strict();

export type UpdateDocumentMetadataInput = z.infer<typeof UpdateDocumentMetadataSchema>;

export const ReclassifyDocumentSchema = z
  .object({
    classificationLevelId: z.coerce.bigint().positive(),
    businessCategoryId: z.coerce.bigint().positive(),
    reason: z.string().trim().min(1).max(500),
  })
  .strict();

export type ReclassifyDocumentInput = z.infer<typeof ReclassifyDocumentSchema>;

export const SetCurrentVersionSchema = z
  .object({
    versionNo: z.number().int().positive().optional(),
    versionId: z.coerce.bigint().positive().optional(),
  })
  .strict();

export type SetCurrentVersionInput = z.infer<typeof SetCurrentVersionSchema>;

export const TransferDocumentOwnerSchema = z
  .object({
    newOwnerId: z.coerce.bigint().positive(),
    reason: z.string().trim().min(1).max(500),
  })
  .strict();

export type TransferDocumentOwnerInput = z.infer<typeof TransferDocumentOwnerSchema>;

export const ArchiveDocumentSchema = z
  .object({
    reason: z.string().max(500).optional(),
  })
  .strict();

export type ArchiveDocumentInput = z.infer<typeof ArchiveDocumentSchema>;

export const SearchDocumentsSchema = z
  .object({
    q: z.string().max(200).optional(),
    status: z.enum(['DRAFT', 'ACTIVE', 'ARCHIVED']).optional(),
    departmentId: z.coerce.bigint().positive().optional(),
    classificationLevelId: z.coerce.bigint().positive().optional(),
    sort: z.enum(['created_at', 'updated_at', 'title']).default('created_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type SearchDocumentsInput = z.infer<typeof SearchDocumentsSchema>;

export const MyGrantedDocumentsSchema = z
  .object({
    sort: z.enum(['granted_at', 'valid_until', 'title']).default('granted_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type MyGrantedDocumentsInput = z.infer<typeof MyGrantedDocumentsSchema>;

// --- Access Grant Schemas ---

export const GrantPermissionSchema = z.enum(['VIEW', 'DOWNLOAD']);
export type GrantPermission = z.infer<typeof GrantPermissionSchema>;

export const CreateAccessGrantSchema = z
  .object({
    documentId: z.string().uuid(),
    principalType: z.enum(['USER', 'ROLE']),
    principalUserId: z.coerce.bigint().positive().optional(),
    principalRoleId: z.coerce.bigint().positive().optional(),
    permissions: z.array(GrantPermissionSchema).min(1).max(2),
    validFrom: z.string().datetime({ offset: true }),
    validUntil: z.string().datetime({ offset: true }),
  })
  .strict()
  .superRefine((data, ctx) => {
    // Exactly one principal must be provided
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
    // validUntil must be after validFrom
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
    status: z.enum(['ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED']).optional(),
    principalType: z.enum(['USER', 'ROLE']).optional(),
    sort: z.enum(['granted_at', 'valid_until', 'status']).default('granted_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type ListAccessGrantsInput = z.infer<typeof ListAccessGrantsSchema>;
