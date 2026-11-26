import { z } from 'zod';
import {
  isNotPastIsoCalendarDate,
  isValidIsoCalendarDate,
  PositiveBigIntSchema,
} from './validation-primitives.js';

const RetentionCalendarDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/u, 'Retention date must be in YYYY-MM-DD format')
  .refine(isValidIsoCalendarDate, 'Invalid calendar retention date')
  .refine((value) => isNotPastIsoCalendarDate(value), 'Retention date cannot be in the past');

/**
 * Thuật toán: Kiểm định khóa nguyên dương an toàn trong miền IEEE-754 (`1 <= id <= Number.MAX_SAFE_INTEGER`)
 * chống làm tròn tĩnh hoặc tràn số khi phân tích tham số đường dẫn.
 */
export const IdParamSchema = z
  .object({
    id: z.union([
      z.number().int().positive().safe('Identifier exceeds IEEE-754 MAX_SAFE_INTEGER'),
      z
        .string()
        .trim()
        .regex(/^[1-9]\d*$/u, 'Identifier must be a positive integer')
        .transform((val) => Number(val))
        .pipe(z.number().int().positive().safe('Identifier exceeds IEEE-754 MAX_SAFE_INTEGER')),
    ]),
  })
  .strict();

export const UuidParamSchema = z
  .object({
    id: z.string().uuid(),
  })
  .strict();

// CONFLICT-RESOLVED: Áp dụng kiểm tra giới hạn BIGINT 64-bit, ngày lịch Gregorian thực và ràng buộc đi kèm cặp ID phân loại ban đầu cho toàn bộ lược đồ tài liệu.
export const CreateDocumentDraftSchema = z
  .object({
    title: z.string().trim().min(1).max(255),
    departmentId: PositiveBigIntSchema,
    description: z.string().max(2000).optional(),
    documentCode: z
      .string()
      .trim()
      .regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/, 'Invalid documentCode format')
      .optional(),
    retentionUntil: RetentionCalendarDateSchema.optional(),
    classificationLevelId: PositiveBigIntSchema.optional(),
    businessCategoryId: PositiveBigIntSchema.optional(),
    reason: z.string().max(500).optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    const hasLevel = data.classificationLevelId !== undefined;
    const hasCategory = data.businessCategoryId !== undefined;
    if (hasLevel !== hasCategory) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [hasLevel ? 'businessCategoryId' : 'classificationLevelId'],
        message:
          'classificationLevelId and businessCategoryId must be provided together when classifying a document draft.',
      });
    }
  });

export type CreateDocumentDraftInput = z.infer<typeof CreateDocumentDraftSchema>;

export const UpdateDocumentMetadataSchema = z
  .object({
    title: z.string().trim().min(1).max(255).optional(),
    description: z.string().max(2000).nullable().optional(),
    departmentId: PositiveBigIntSchema.optional(),
    retentionUntil: RetentionCalendarDateSchema.nullable().optional(),
  })
  .strict();

export type UpdateDocumentMetadataInput = z.infer<typeof UpdateDocumentMetadataSchema>;

export const ReclassifyDocumentSchema = z
  .object({
    classificationLevelId: PositiveBigIntSchema,
    businessCategoryId: PositiveBigIntSchema,
    reason: z.string().trim().min(1).max(500),
  })
  .strict();

export type ReclassifyDocumentInput = z.infer<typeof ReclassifyDocumentSchema>;

export const SetCurrentVersionSchema = z
  .object({
    versionNo: z.number().int().positive().optional(),
    versionId: PositiveBigIntSchema.optional(),
  })
  .strict()
  .refine((data) => data.versionNo !== undefined || data.versionId !== undefined, {
    message: 'Either versionNo or versionId must be provided.',
  });

export type SetCurrentVersionInput = z.infer<typeof SetCurrentVersionSchema>;

export const TransferDocumentOwnerSchema = z
  .object({
    newOwnerId: PositiveBigIntSchema,
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
    scope: z.enum(['all', 'owned']).default('all'),
    status: z.enum(['DRAFT', 'ACTIVE', 'ARCHIVED']).optional(),
    departmentId: PositiveBigIntSchema.optional(),
    classificationLevelId: PositiveBigIntSchema.optional(),
    classificationCode: z
      .enum(['UNCLASSIFIED', 'INTERNAL', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'])
      .optional(),
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
