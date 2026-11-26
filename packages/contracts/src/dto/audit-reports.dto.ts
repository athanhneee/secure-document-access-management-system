import { z } from 'zod';
import { IsoDateOrDateTimeSchema, PositiveBigIntSchema } from './validation-primitives.js';

/**
 * Module: Audit Trail, Anchors, Async Exports & Notifications DTO Schemas (`@sda/contracts`)
 * Thuật toán: Xác thực nghiêm ngặt bộ lọc truy vấn kiểm toán, khoảng số thứ tự chuỗi `BIGINT` 64-bit và tham số tác vụ xuất báo cáo bất đồng bộ.
 */
const AuditOutcomeSchema = z.enum(['SUCCESS', 'DENIED', 'FAILED']);

const OptionalCorrelationIdSchema = z.preprocess((val) => {
  if (val === undefined || val === null) return undefined;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    return trimmed.length === 0 ? undefined : trimmed;
  }
  return val;
}, z.string().uuid('correlationId must be a valid UUID').optional());

const OptionalPartitionSchema = z.preprocess((val) => {
  if (val === undefined || val === null) return undefined;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    return trimmed.length === 0 ? undefined : trimmed;
  }
  return val;
}, z.string().min(1).max(80).optional());

/**
 * Thuật toán: Giới hạn kích thước đối tượng tham số lọc xuất báo cáo (`filterParams`) chống tấn công phình bộ nhớ JSONB:
 *   - Tối đa 30 khóa cấp 1, mỗi tên khóa tối đa 80 ký tự.
 *   - Tổng kích thước tuần tự hóa `JSON.stringify` không vượt quá 8192 ký tự.
 */
const BoundedExportFilterParamsSchema = z
  .record(z.string().min(1).max(80), z.unknown())
  .default({})
  .superRefine((val, ctx) => {
    const keys = Object.keys(val);
    if (keys.length > 30) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'filterParams cannot contain more than 30 keys.',
      });
      return;
    }
    try {
      const serialized = JSON.stringify(val);
      if (serialized.length > 8192) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'filterParams payload exceeds maximum allowed size (8192 bytes).',
        });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'filterParams must be valid JSON-serializable data.',
      });
    }
  });

// CONFLICT-RESOLVED: Chuẩn hóa actorUserId/fromSequence/toSequence theo giới hạn BIGINT 64-bit, UUID correlationId và kiểm tra ngày lịch thực cho from/to.
export const QueryAuditLogsSchema = z
  .object({
    actorUserId: PositiveBigIntSchema.optional(),
    actorUsername: z.string().max(80).optional(),
    documentId: z.string().uuid().optional(),
    action: z.string().max(100).optional(),
    outcome: AuditOutcomeSchema.optional(),
    chainPartition: z.string().max(80).optional(),
    correlationId: OptionalCorrelationIdSchema,
    from: IsoDateOrDateTimeSchema.optional(),
    to: IsoDateOrDateTimeSchema.optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20),
    sort: z.enum(['occurred_at', 'chain_sequence']).default('occurred_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();

export type QueryAuditLogsInput = z.infer<typeof QueryAuditLogsSchema>;

export const ExportAuditLogsSchema = z
  .object({
    format: z.enum(['CSV', 'JSON']).default('JSON'),
    actorUserId: PositiveBigIntSchema.optional(),
    actorUsername: z.string().max(80).optional(),
    documentId: z.string().uuid().optional(),
    action: z.string().max(100).optional(),
    outcome: AuditOutcomeSchema.optional(),
    chainPartition: z.string().max(80).optional(),
    correlationId: OptionalCorrelationIdSchema,
    from: IsoDateOrDateTimeSchema.optional(),
    to: IsoDateOrDateTimeSchema.optional(),
    limit: z.coerce.number().int().min(1).max(10000).default(1000),
  })
  .strict();

export type ExportAuditLogsInput = z.infer<typeof ExportAuditLogsSchema>;

export const CreateAuditAnchorSchema = z
  .object({
    chainPartition: z.string().min(1).max(80),
  })
  .strict();

const OptionalBooleanQuerySchema = z.preprocess((val) => {
  if (val === undefined || val === null || val === '') return undefined;
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') {
    const lower = val.trim().toLowerCase();
    if (lower === 'true' || lower === '1') return true;
    if (lower === 'false' || lower === '0') return false;
  }
  return val;
}, z.boolean().optional());

export const VerifyAuditChainSchema = z
  .object({
    chainPartition: OptionalPartitionSchema,
    fromSequence: PositiveBigIntSchema.optional(),
    toSequence: PositiveBigIntSchema.optional(),
    fullScan: OptionalBooleanQuerySchema,
  })
  .strict()
  .superRefine((data, ctx) => {
    if (
      (data.fromSequence !== undefined || data.toSequence !== undefined) &&
      !data.chainPartition
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['chainPartition'],
        message: 'chainPartition is required when fromSequence or toSequence is specified.',
      });
    }
    if (
      data.fromSequence !== undefined &&
      data.toSequence !== undefined &&
      data.fromSequence > data.toSequence
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['fromSequence'],
        message: 'fromSequence must not be greater than toSequence.',
      });
    }
  });

export type VerifyAuditChainInput = z.infer<typeof VerifyAuditChainSchema>;

const ExportFormatSchema = z.enum(['CSV', 'EXCEL', 'PDF', 'JSON']);
export type ExportFormat = z.infer<typeof ExportFormatSchema>;

const ExportTypeSchema = z.enum([
  'AUDIT_LOGS',
  'SECURITY_ALERTS',
  'INCIDENT_REPORTS',
  'SYSTEM_REPORT',
]);
export type ExportType = z.infer<typeof ExportTypeSchema>;

export const CreateExportJobSchema = z
  .object({
    exportType: ExportTypeSchema,
    format: ExportFormatSchema.default('CSV'),
    filterParams: BoundedExportFilterParamsSchema,
  })
  .strict();

export type CreateExportJobInput = z.infer<typeof CreateExportJobSchema>;

export const QueryNotificationsSchema = z
  .object({
    status: z.enum(['UNREAD', 'READ', 'ARCHIVED']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type QueryNotificationsInput = z.infer<typeof QueryNotificationsSchema>;
