import { z } from 'zod';
import { IsoDateOrDateTimeSchema, PositiveBigIntSchema } from './validation-primitives.js';

export const AlertStatusSchema = z.enum(['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']);
export type AlertStatus = z.infer<typeof AlertStatusSchema>;

export const SeverityLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type SeverityLevel = z.infer<typeof SeverityLevelSchema>;

export const QuerySecurityAlertsSchema = z
  .object({
    status: AlertStatusSchema.optional(),
    severity: SeverityLevelSchema.optional(),
    alertType: z.string().max(80).optional(),
    detectedUserId: PositiveBigIntSchema.optional(),
    documentId: z.string().uuid().optional(),
    assignedTo: PositiveBigIntSchema.optional(),
    from: IsoDateOrDateTimeSchema.optional(),
    to: IsoDateOrDateTimeSchema.optional(),
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
    assignedToUserId: PositiveBigIntSchema.nullable(),
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
    submittedToOwner: PositiveBigIntSchema.optional(),
    submittedToAdmin: PositiveBigIntSchema.optional(),
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
    assignedTo: PositiveBigIntSchema.optional(),
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
    preparedBy: PositiveBigIntSchema.optional(),
    alertId: z.string().uuid().optional(),
    from: IsoDateOrDateTimeSchema.optional(),
    to: IsoDateOrDateTimeSchema.optional(),
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
    parameters: z.record(z.string(), z.unknown()).optional(),
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
