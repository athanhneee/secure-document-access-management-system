/**
 * Module: Unit Tests for `@sda/contracts` Boundary Validation Schemas
 * Thuật toán: Kiểm chứng biên số nguyên 64-bit PostgreSQL BIGINT, ngày lịch Gregorian thực và định dạng UUID.
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  buildAuditKeyRing,
  canonicalizeJson,
  CreateAccessRequestSchema,
  CreateDocumentDraftSchema,
  CreateExportJobSchema,
  ExportAuditLogsSchema,
  getCurrentUtcIsoDate,
  IdParamSchema,
  isNotPastIsoCalendarDate,
  isValidIsoCalendarDate,
  MAX_PG_BIGINT,
  PositiveBigIntSchema,
  QueryAuditLogsSchema,
  RunDetectionInputSchema,
  SearchDocumentsSchema,
  SetCurrentVersionSchema,
  UpdateDocumentMetadataSchema,
  VerifyAuditChainSchema,
} from '../dist/index.js';

test('isValidIsoCalendarDate — accepts real Gregorian dates including leap day and rejects impossible calendar dates', () => {
  assert.equal(isValidIsoCalendarDate('2026-02-28'), true);
  assert.equal(isValidIsoCalendarDate('2024-02-29'), true);
  assert.equal(isValidIsoCalendarDate('2025-02-29'), false);
  assert.equal(isValidIsoCalendarDate('2026-02-31'), false);
  assert.equal(isValidIsoCalendarDate('2026-04-31'), false);
  assert.equal(isValidIsoCalendarDate('2026-13-01'), false);
  assert.equal(isValidIsoCalendarDate('2026/02/28'), false);
});

test('isNotPastIsoCalendarDate & retention DTOs — reject past dates while accepting today, future, and null updates', () => {
  const refDate = new Date('2026-11-25T12:00:00.000Z');
  assert.equal(getCurrentUtcIsoDate(refDate), '2026-11-25');
  assert.equal(isNotPastIsoCalendarDate('2026-11-24', refDate), false);
  assert.equal(isNotPastIsoCalendarDate('2026-11-25', refDate), true);
  assert.equal(isNotPastIsoCalendarDate('2026-11-26', refDate), true);
  assert.equal(isNotPastIsoCalendarDate('2026-02-31', refDate), false);

  const todayIso = getCurrentUtcIsoDate();
  const yesterdayIso = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  const tomorrowIso = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);

  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Past Retention Draft',
      departmentId: '1',
      retentionUntil: yesterdayIso,
    }).success,
    false,
  );
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Today Retention Draft',
      departmentId: '1',
      retentionUntil: todayIso,
    }).success,
    true,
  );
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Future Retention Draft',
      departmentId: '1',
      retentionUntil: tomorrowIso,
    }).success,
    true,
  );
  assert.equal(
    UpdateDocumentMetadataSchema.safeParse({ retentionUntil: yesterdayIso }).success,
    false,
  );
  assert.equal(UpdateDocumentMetadataSchema.safeParse({ retentionUntil: todayIso }).success, true);
  assert.equal(UpdateDocumentMetadataSchema.safeParse({ retentionUntil: null }).success, true);
});

test('PositiveBigIntSchema & DTOs — enforce 64-bit signed PostgreSQL BIGINT ceiling and reject invalid dates', () => {
  assert.equal(PositiveBigIntSchema.parse('9223372036854775807'), MAX_PG_BIGINT);
  assert.equal(PositiveBigIntSchema.safeParse('9223372036854775808').success, false);
  assert.equal(PositiveBigIntSchema.safeParse('0').success, false);
  assert.equal(PositiveBigIntSchema.safeParse('-5').success, false);
  assert.equal(PositiveBigIntSchema.safeParse(true).success, false);

  assert.equal(
    QueryAuditLogsSchema.safeParse({
      actorUserId: '9223372036854775808',
    }).success,
    false,
  );
  assert.equal(
    QueryAuditLogsSchema.safeParse({
      from: '2026-02-31',
    }).success,
    false,
  );
  assert.equal(
    QueryAuditLogsSchema.safeParse({
      from: '2026-02-28',
      to: '2026-03-01T00:00:00Z',
    }).success,
    true,
  );
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Test Document',
      departmentId: '1',
      retentionUntil: '2026-02-31',
    }).success,
    false,
  );
  assert.equal(
    VerifyAuditChainSchema.safeParse({
      fromSequence: '9223372036854775809',
    }).success,
    false,
  );
});

test('[BUG-112] DTO boundary hardening — safe IdParam, paired draft classification, non-empty SetCurrentVersion, request interval, sequence range, UNCLASSIFIED, UUID correlationId & payload bounds', () => {
  // 1. IdParamSchema safe integer bounds
  assert.equal(IdParamSchema.safeParse({ id: '42' }).success, true);
  assert.equal(IdParamSchema.safeParse({ id: String(Number.MAX_SAFE_INTEGER) }).success, true);
  assert.equal(IdParamSchema.safeParse({ id: '9007199254740992' }).success, false);
  assert.equal(IdParamSchema.safeParse({ id: '99999999999999999999' }).success, false);
  assert.equal(IdParamSchema.safeParse({ id: '1e5' }).success, false);

  // 2. CreateDocumentDraftSchema requires paired classificationLevelId + businessCategoryId
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Lone Level Draft',
      departmentId: '1',
      classificationLevelId: '2',
    }).success,
    false,
  );
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Lone Category Draft',
      departmentId: '1',
      businessCategoryId: '3',
    }).success,
    false,
  );
  assert.equal(
    CreateDocumentDraftSchema.safeParse({
      title: 'Paired Draft',
      departmentId: '1',
      classificationLevelId: '2',
      businessCategoryId: '3',
    }).success,
    true,
  );

  // 3. SetCurrentVersionSchema rejects {}
  assert.equal(SetCurrentVersionSchema.safeParse({}).success, false);
  assert.equal(SetCurrentVersionSchema.safeParse({ versionNo: 2 }).success, true);
  assert.equal(SetCurrentVersionSchema.safeParse({ versionId: '10' }).success, true);

  // 4. CreateAccessRequestSchema enforces requestedUntil > requestedFrom
  const docId = randomUUID();
  assert.equal(
    CreateAccessRequestSchema.safeParse({
      documentId: docId,
      reason: 'Can xem tai lieu phuc vu kiem tra dinh ky.',
      requestedFrom: '2026-11-26T10:00:00Z',
      requestedUntil: '2026-11-26T09:00:00Z',
    }).success,
    false,
  );
  assert.equal(
    CreateAccessRequestSchema.safeParse({
      documentId: docId,
      reason: 'Can xem tai lieu phuc vu kiem tra dinh ky.',
      requestedFrom: '2026-11-26T10:00:00Z',
      requestedUntil: '2026-11-26T12:00:00Z',
    }).success,
    true,
  );

  // 5. VerifyAuditChainSchema requires chainPartition for sequence bounds & rejects fromSequence > toSequence
  assert.equal(
    VerifyAuditChainSchema.safeParse({ fromSequence: '1', toSequence: '10' }).success,
    false,
  );
  assert.equal(
    VerifyAuditChainSchema.safeParse({
      chainPartition: 'GLOBAL',
      fromSequence: '20',
      toSequence: '10',
    }).success,
    false,
  );
  assert.equal(
    VerifyAuditChainSchema.safeParse({
      chainPartition: 'GLOBAL',
      fromSequence: '1',
      toSequence: '10',
    }).success,
    true,
  );

  // 6. SearchDocumentsSchema supports UNCLASSIFIED
  assert.equal(
    SearchDocumentsSchema.safeParse({ classificationCode: 'UNCLASSIFIED' }).success,
    true,
  );

  // 7. correlationId requires valid UUID
  const corrId = randomUUID();
  assert.equal(QueryAuditLogsSchema.safeParse({ correlationId: 'not-a-uuid' }).success, false);
  assert.equal(QueryAuditLogsSchema.safeParse({ correlationId: corrId }).success, true);
  assert.equal(QueryAuditLogsSchema.safeParse({ correlationId: '   ' }).success, true);
  assert.equal(ExportAuditLogsSchema.safeParse({ correlationId: 'bad' }).success, false);
  assert.equal(ExportAuditLogsSchema.safeParse({ correlationId: corrId }).success, true);

  // 8. RunDetectionInputSchema & CreateExportJobSchema size bounds
  assert.equal(
    RunDetectionInputSchema.safeParse({
      ruleCodes: Array.from({ length: 51 }, (_, i) => `RULE_${i}`),
    }).success,
    false,
  );
  assert.equal(RunDetectionInputSchema.safeParse({ ruleCodes: [''] }).success, false);
  assert.equal(RunDetectionInputSchema.safeParse({ ruleCodes: ['MASS_DOWNLOAD'] }).success, true);

  const tooManyFilterKeys = Object.fromEntries(
    Array.from({ length: 31 }, (_, i) => [`key_${i}`, 'v']),
  );
  assert.equal(
    CreateExportJobSchema.safeParse({
      exportType: 'AUDIT_LOGS',
      filterParams: tooManyFilterKeys,
    }).success,
    false,
  );
  assert.equal(
    CreateExportJobSchema.safeParse({
      exportType: 'AUDIT_LOGS',
      filterParams: { oversized: 'x'.repeat(9000) },
    }).success,
    false,
  );
});

test('[BUG-125] canonicalizeJson handles invalid Date without RangeError & buildAuditKeyRing throws on unconfigured version >= 2', () => {
  assert.equal(canonicalizeJson(new Date('not-a-date')), 'null');
  assert.equal(canonicalizeJson({ b: 1, a: new Date(Number.NaN) }), '{"a":null,"b":1}');
  assert.equal(
    canonicalizeJson(new Date('2026-11-26T00:00:00.000Z')),
    '"2026-11-26T00:00:00.000Z"',
  );

  const primaryKey = 'v1-primary-audit-hmac-key-at-least-32-bytes!!';
  const rotatedKey = 'v2-rotated-audit-hmac-key-at-least-32-bytes!!';
  const ring = buildAuditKeyRing(primaryKey, JSON.stringify({ 2: rotatedKey }));
  assert.equal(ring.getKey(1), primaryKey);
  assert.equal(ring.getKey(2), rotatedKey);
  assert.throws(() => ring.getKey(3), /Missing audit HMAC key configuration for version 3/);
});
