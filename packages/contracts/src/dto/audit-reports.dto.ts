import { z } from 'zod';

export const AuditOutcomeSchema = z.enum(['SUCCESS', 'DENIED', 'FAILED']);
export type AuditOutcome = z.infer<typeof AuditOutcomeSchema>;

export const QueryAuditLogsSchema = z
  .object({
    actorUserId: z.coerce.bigint().positive().optional(),
    documentId: z.string().uuid().optional(),
    action: z.string().max(100).optional(),
    outcome: AuditOutcomeSchema.optional(),
    chainPartition: z.string().max(80).optional(),
    from: z
      .string()
      .datetime({ offset: true })
      .or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/))
      .optional(),
    to: z
      .string()
      .datetime({ offset: true })
      .or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/))
      .optional(),
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
    actorUserId: z.coerce.bigint().positive().optional(),
    documentId: z.string().uuid().optional(),
    action: z.string().max(100).optional(),
    outcome: AuditOutcomeSchema.optional(),
    chainPartition: z.string().max(80).optional(),
    from: z
      .string()
      .datetime({ offset: true })
      .or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/))
      .optional(),
    to: z
      .string()
      .datetime({ offset: true })
      .or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/))
      .optional(),
    limit: z.coerce.number().int().min(1).max(10000).default(1000),
  })
  .strict();

export type ExportAuditLogsInput = z.infer<typeof ExportAuditLogsSchema>;

export const CreateAuditAnchorSchema = z
  .object({
    chainPartition: z.string().min(1).max(80),
  })
  .strict();

export type CreateAuditAnchorInput = z.infer<typeof CreateAuditAnchorSchema>;

export const VerifyAuditChainSchema = z
  .object({
    chainPartition: z.string().max(80).optional(),
    fromSequence: z.coerce.bigint().positive().optional(),
    toSequence: z.coerce.bigint().positive().optional(),
  })
  .strict();

export type VerifyAuditChainInput = z.infer<typeof VerifyAuditChainSchema>;

export const ExportFormatSchema = z.enum(['CSV', 'EXCEL', 'PDF', 'JSON']);
export type ExportFormat = z.infer<typeof ExportFormatSchema>;

export const ExportTypeSchema = z.enum([
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
    filterParams: z.record(z.string(), z.unknown()).default({}),
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
