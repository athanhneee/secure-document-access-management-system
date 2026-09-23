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

// --- Controlled Document Delivery & Access Session Schemas (Prompt 13) ---

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

export type PreviewPageParamInput = z.infer<typeof PreviewPageParamSchema>;

export const DownloadTicketParamSchema = z
  .object({
    ticket: z.string().regex(/^DT-[0-9a-f]{64}$/i, 'Invalid download ticket format'),
  })
  .strict();

export type DownloadTicketParamInput = z.infer<typeof DownloadTicketParamSchema>;

export const WatermarkTokenParamSchema = z
  .object({
    token: z.string().regex(/^WM-[0-9a-f]{16,64}$/i, 'Invalid watermark token format'),
  })
  .strict();

export type WatermarkTokenParamInput = z.infer<typeof WatermarkTokenParamSchema>;

// --- Hardened Audit Trail Schemas (Prompt 14) ---

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

// --- Security Operations, Alerts & Incidents Schemas (Prompt 15) ---

export const AlertStatusSchema = z.enum(['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']);
export type AlertStatus = z.infer<typeof AlertStatusSchema>;

export const SeverityLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type SeverityLevel = z.infer<typeof SeverityLevelSchema>;

export const QuerySecurityAlertsSchema = z
  .object({
    status: AlertStatusSchema.optional(),
    severity: SeverityLevelSchema.optional(),
    alertType: z.string().max(80).optional(),
    detectedUserId: z.coerce.bigint().positive().optional(),
    documentId: z.string().uuid().optional(),
    assignedTo: z.coerce.bigint().positive().optional(),
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
    sort: z.enum(['detected_at', 'severity']).default('detected_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();

export type QuerySecurityAlertsInput = z.infer<typeof QuerySecurityAlertsSchema>;

export const UpdateAlertStatusSchema = z
  .object({
    status: AlertStatusSchema,
    resolutionNote: z.string().trim().max(1000).optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    if (
      (data.status === 'RESOLVED' || data.status === 'FALSE_POSITIVE') &&
      (!data.resolutionNote || data.resolutionNote.length < 5)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['resolutionNote'],
        message:
          'resolutionNote of at least 5 characters is required when resolving or marking false positive.',
      });
    }
  });

export type UpdateAlertStatusInput = z.infer<typeof UpdateAlertStatusSchema>;

export const AssignAlertSchema = z
  .object({
    assignedToUserId: z.coerce.bigint().positive().nullable(),
  })
  .strict();

export type AssignAlertInput = z.infer<typeof AssignAlertSchema>;

export const AddAlertNoteSchema = z
  .object({
    note: z.string().trim().min(5, 'Investigation note must be at least 5 characters.').max(2000),
  })
  .strict();

export type AddAlertNoteInput = z.infer<typeof AddAlertNoteSchema>;

export const IncidentStatusSchema = z.enum(['DRAFT', 'SUBMITTED', 'IN_REVIEW', 'CLOSED']);
export type IncidentStatus = z.infer<typeof IncidentStatusSchema>;

export const CreateIncidentReportSchema = z
  .object({
    alertId: z.string().uuid().optional(),
    title: z.string().trim().min(5, 'Title must be at least 5 characters.').max(255),
    summary: z.string().trim().min(10, 'Summary must be at least 10 characters.').max(5000),
    findings: z.string().trim().max(5000).optional(),
    impactAssessment: z.string().trim().max(5000).optional(),
  })
  .strict();

export type CreateIncidentReportInput = z.infer<typeof CreateIncidentReportSchema>;

export const UpdateIncidentReportSchema = z
  .object({
    title: z.string().trim().min(5).max(255).optional(),
    summary: z.string().trim().min(10).max(5000).optional(),
    findings: z.string().trim().max(5000).optional(),
    impactAssessment: z.string().trim().max(5000).optional(),
  })
  .strict();

export type UpdateIncidentReportInput = z.infer<typeof UpdateIncidentReportSchema>;

export const SubmitIncidentReportSchema = z
  .object({
    submittedToOwner: z.coerce.bigint().positive().optional(),
    submittedToAdmin: z.coerce.bigint().positive().optional(),
  })
  .strict();

export type SubmitIncidentReportInput = z.infer<typeof SubmitIncidentReportSchema>;

export const CloseIncidentReportSchema = z
  .object({
    closingNote: z.string().trim().min(5).max(1000).optional(),
  })
  .strict();

export type CloseIncidentReportInput = z.infer<typeof CloseIncidentReportSchema>;

export const CreateIncidentActionSchema = z
  .object({
    actionType: z.string().trim().min(3).max(80),
    recommendation: z.string().trim().min(5).max(2000),
    assignedTo: z.coerce.bigint().positive().optional(),
    dueAt: z.string().datetime({ offset: true }).optional(),
  })
  .strict();

export type CreateIncidentActionInput = z.infer<typeof CreateIncidentActionSchema>;

export const CompleteIncidentActionSchema = z
  .object({
    completionNote: z
      .string()
      .trim()
      .min(5, 'Completion note must be at least 5 characters.')
      .max(2000),
  })
  .strict();

export type CompleteIncidentActionInput = z.infer<typeof CompleteIncidentActionSchema>;

export const QueryIncidentReportsSchema = z
  .object({
    status: IncidentStatusSchema.optional(),
    preparedBy: z.coerce.bigint().positive().optional(),
    alertId: z.string().uuid().optional(),
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
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
    sort: z.enum(['created_at', 'submitted_at', 'status']).default('created_at'),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();

export type QueryIncidentReportsInput = z.infer<typeof QueryIncidentReportsSchema>;

export const UpdateDetectionRuleConfigSchema = z
  .object({
    isEnabled: z.boolean().optional(),
    severity: SeverityLevelSchema.optional(),
    threshold: z.number().int().min(1).max(1000).optional(),
    windowMinutes: z.number().int().min(1).max(1440).optional(),
    cooldownMinutes: z.number().int().min(1).max(1440).optional(),
    parameters: z.record(z.unknown()).optional(),
  })
  .strict();

export type UpdateDetectionRuleConfigInput = z.infer<typeof UpdateDetectionRuleConfigSchema>;

export const RunDetectionInputSchema = z
  .object({
    ruleCodes: z.array(z.string()).optional(),
    windowMinutes: z.number().int().min(1).max(1440).optional(),
  })
  .strict();

export type RunDetectionInput = z.infer<typeof RunDetectionInputSchema>;

// --- Async Export Job Schemas ---

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
    filterParams: z.record(z.unknown()).default({}),
  })
  .strict();

export type CreateExportJobInput = z.infer<typeof CreateExportJobSchema>;

// --- Notification Schemas ---

export const QueryNotificationsSchema = z
  .object({
    status: z.enum(['UNREAD', 'READ', 'ARCHIVED']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export type QueryNotificationsInput = z.infer<typeof QueryNotificationsSchema>;
