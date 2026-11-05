/**
 * Module: Unit Tests for `@sda/contracts` Boundary Validation Schemas
 * Thuật toán: Kiểm chứng biên số nguyên 64-bit PostgreSQL BIGINT, ngày lịch Gregorian thực và định dạng UUID.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CreateDocumentDraftSchema,
  isValidIsoCalendarDate,
  MAX_PG_BIGINT,
  PositiveBigIntSchema,
  QueryAuditLogsSchema,
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
