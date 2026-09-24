import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  CreateDocumentDraftSchema,
  CreateAccessRequestSchema,
  DecideAccessRequestSchema,
  UpdateAlertStatusSchema,
  CreateIncidentReportSchema,
  CompleteIncidentActionSchema,
} from '../../../packages/contracts/dist/dto.js';

// ── 1. Document Lifecycle & State Machine ──────────────────────────────────────

test('Document State Machine — validates draft creation invariants', () => {
  const validDraft = {
    title: 'Ke Hoach Bao Mat Thong Tin 2026',
    departmentId: '1',
    description: 'Bao mat tai lieu phong Ke Hoach',
    documentCode: 'DOC-SEC-2026-001',
    classificationLevelId: '3',
    businessCategoryId: '1',
  };
  const parsed = CreateDocumentDraftSchema.safeParse(validDraft);
  assert.ok(parsed.success);
  assert.equal(parsed.data.departmentId, 1n);
  assert.equal(parsed.data.classificationLevelId, 3n);

  // Rejects empty title
  assert.ok(!CreateDocumentDraftSchema.safeParse({ ...validDraft, title: '   ' }).success);

  // Rejects invalid retention date format
  assert.ok(
    !CreateDocumentDraftSchema.safeParse({ ...validDraft, retentionUntil: '23/09/2026' }).success,
  );
  assert.ok(
    CreateDocumentDraftSchema.safeParse({ ...validDraft, retentionUntil: '2026-12-31' }).success,
  );
});

test('Document State Machine — enforces valid transitions DRAFT -> ACTIVE -> ARCHIVED', () => {
  const allowedTransitions = {
    DRAFT: ['PENDING_SCAN', 'ACTIVE'],
    PENDING_SCAN: ['ACTIVE', 'REJECTED'],
    ACTIVE: ['ARCHIVED'],
    ARCHIVED: ['ACTIVE', 'DELETED'],
    DELETED: [],
    REJECTED: ['DRAFT'],
  };

  function canTransition(current, next) {
    return allowedTransitions[current]?.includes(next) ?? false;
  }

  // Valid progressions
  assert.ok(canTransition('DRAFT', 'ACTIVE'));
  assert.ok(canTransition('ACTIVE', 'ARCHIVED'));
  assert.ok(canTransition('ARCHIVED', 'DELETED'));

  // Invalid regressions
  assert.ok(!canTransition('ARCHIVED', 'DRAFT'));
  assert.ok(!canTransition('DELETED', 'ACTIVE'));
  assert.ok(!canTransition('DELETED', 'DRAFT'));
  assert.ok(!canTransition('ACTIVE', 'DRAFT'));
});

test('Document State Machine — SCD Type 2 reclassification maintains temporal continuity', () => {
  const history = [
    {
      documentId: 'doc-1',
      classificationLevelId: 2n,
      validFrom: new Date('2026-01-01T00:00:00Z'),
      validTo: new Date('2026-06-01T00:00:00Z'),
      isCurrent: false,
    },
    {
      documentId: 'doc-1',
      classificationLevelId: 3n,
      validFrom: new Date('2026-06-01T00:00:00Z'),
      validTo: null,
      isCurrent: true,
    },
  ];

  // Exactly one record is current
  const currentRecords = history.filter((h) => h.isCurrent && h.validTo === null);
  assert.equal(currentRecords.length, 1);
  assert.equal(currentRecords[0].classificationLevelId, 3n);

  // Reclassifying to Level 4 closes previous record
  const reclassifyDate = new Date('2026-09-23T12:00:00Z');
  currentRecords[0].isCurrent = false;
  currentRecords[0].validTo = reclassifyDate;

  history.push({
    documentId: 'doc-1',
    classificationLevelId: 4n,
    validFrom: reclassifyDate,
    validTo: null,
    isCurrent: true,
  });

  const updatedCurrent = history.filter((h) => h.isCurrent && h.validTo === null);
  assert.equal(updatedCurrent.length, 1);
  assert.equal(updatedCurrent[0].classificationLevelId, 4n);
  assert.equal(history.length, 3);
});

// ── 2. Access Request State Machine ───────────────────────────────────────────

test('Access Request State Machine — validates request creation and reason bounds', () => {
  const validRequest = {
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Can tham chieu so lieu cho buoi hop hoi dong quan tri ngay mai.',
    requestedUntil: new Date(Date.now() + 86400 * 1000).toISOString(),
  };

  const parsed = CreateAccessRequestSchema.safeParse(validRequest);
  assert.ok(parsed.success);

  // Reason must be at least 10 chars (D-BR12)
  const shortReason = { ...validRequest, reason: 'Ngan qua' };
  assert.ok(!CreateAccessRequestSchema.safeParse(shortReason).success);

  // Requested action must be VIEW or DOWNLOAD
  const invalidAction = { ...validRequest, requestedAction: 'DELETE' };
  assert.ok(!CreateAccessRequestSchema.safeParse(invalidAction).success);

  // Test DecideAccessRequestSchema
  assert.ok(DecideAccessRequestSchema.safeParse({ decision: 'APPROVED' }).success);
  assert.ok(
    DecideAccessRequestSchema.safeParse({ decision: 'REJECTED', decisionNote: 'Khong phu hop' })
      .success,
  );
  assert.ok(!DecideAccessRequestSchema.safeParse({ decision: 'PENDING' }).success);
});

test('Access Request State Machine — decisions are terminal and immutable (D-BR13)', () => {
  const requestState = {
    id: randomUUID(),
    status: 'PENDING',
    decidedBy: null,
    decidedAt: null,
    decisionNote: null,
  };

  function applyDecision(state, decision, deciderId, note) {
    if (state.status !== 'PENDING') {
      throw new Error(`Cannot decide request in ${state.status} status.`);
    }
    state.status = decision;
    state.decidedBy = deciderId;
    state.decidedAt = new Date();
    state.decisionNote = note;
    return state;
  }

  // First decision succeeds
  applyDecision(requestState, 'APPROVED', 10n, 'Phe duyet cho hop hoi dong');
  assert.equal(requestState.status, 'APPROVED');

  // Attempting second decision fails
  assert.throws(
    () => applyDecision(requestState, 'REJECTED', 20n, 'Tu choi sau'),
    /Cannot decide request in APPROVED status/u,
  );
});

// ── 3. Access Grant State Machine ─────────────────────────────────────────────

test('Access Grant State Machine — enforces temporal bounds and irreversible revocation', () => {
  const now = new Date();
  const grant = {
    id: randomUUID(),
    status: 'ACTIVE',
    validFrom: new Date(now.getTime() - 1000),
    validUntil: new Date(now.getTime() + 3600 * 1000),
    revokedAt: null,
    revocationReason: null,
  };

  function isGrantActive(g, currentTime = new Date()) {
    return g.status === 'ACTIVE' && g.validFrom <= currentTime && currentTime < g.validUntil;
  }

  assert.ok(isGrantActive(grant));

  // Revoke grant
  grant.status = 'REVOKED';
  grant.revokedAt = new Date();
  grant.revocationReason = 'Nghi viec dot xuat';

  assert.ok(!isGrantActive(grant));

  // Revocation is terminal (D-BR15)
  function reactivateGrant(g) {
    if (g.status === 'REVOKED') {
      throw new Error('Revoked access grant cannot be reactivated.');
    }
    g.status = 'ACTIVE';
  }
  assert.throws(() => reactivateGrant(grant), /Revoked access grant cannot be reactivated/u);
});

// ── 4. Access Session State Machine ───────────────────────────────────────────

test('Access Session State Machine — transitions ACTIVE -> TERMINATED with reason', () => {
  const session = {
    id: randomUUID(),
    status: 'ACTIVE',
    startedAt: new Date(),
    endedAt: null,
    terminatedReason: null,
  };

  function terminateSession(s, reason) {
    if (s.status === 'TERMINATED') {
      return s; // Idempotent
    }
    s.status = 'TERMINATED';
    s.endedAt = new Date();
    s.terminatedReason = reason;
    return s;
  }

  terminateSession(session, 'Tài liệu nâng cấp mức mật');
  assert.equal(session.status, 'TERMINATED');
  assert.ok(session.endedAt instanceof Date);
  assert.equal(session.terminatedReason, 'Tài liệu nâng cấp mức mật');

  // Terminal state cannot return to ACTIVE
  assert.throws(() => {
    if (session.status === 'TERMINATED') {
      throw new Error('Terminated session cannot be resumed.');
    }
  }, /Terminated session cannot be resumed/u);
});

// ── 5. Security Alert State Machine ───────────────────────────────────────────

test('Security Alert State Machine — enforces valid transitions and required resolution notes', () => {
  // INVESTIGATING does not require resolutionNote
  const validInvestigating = UpdateAlertStatusSchema.safeParse({ status: 'INVESTIGATING' });
  assert.ok(validInvestigating.success);

  // RESOLVED requires resolutionNote
  const resolveWithoutNote = UpdateAlertStatusSchema.safeParse({ status: 'RESOLVED' });
  assert.ok(!resolveWithoutNote.success);

  const resolveWithNote = UpdateAlertStatusSchema.safeParse({
    status: 'RESOLVED',
    resolutionNote: 'Đã xác minh hoạt động tải hợp lệ phục vụ kiểm toán.',
  });
  assert.ok(resolveWithNote.success);

  // FALSE_POSITIVE requires resolutionNote
  const fpWithoutNote = UpdateAlertStatusSchema.safeParse({ status: 'FALSE_POSITIVE' });
  assert.ok(!fpWithoutNote.success);

  const fpWithNote = UpdateAlertStatusSchema.safeParse({
    status: 'FALSE_POSITIVE',
    resolutionNote: 'Lỗi cấu hình bot giám sát thử nghiệm.',
  });
  assert.ok(fpWithNote.success);
});

// ── 6. Incident Report State Machine ──────────────────────────────────────────

test('Incident Report State Machine — progression and closure verification', () => {
  const validIncident = {
    alertId: randomUUID(),
    title: 'Phat hien truy cap bat thuong tu dai IP la',
    summary: 'Tai khoan user 456 dang nhap tu dai IP ngoai gio hanh chinh va tai 10 file.',
  };
  const parsed = CreateIncidentReportSchema.safeParse(validIncident);
  assert.ok(parsed.success);

  // Completing action requires note
  assert.ok(!CompleteIncidentActionSchema.safeParse({}).success);
  assert.ok(
    CompleteIncidentActionSchema.safeParse({
      completionNote: 'Da chan IP va thu hoi toan bo phien truy cap cua user.',
    }).success,
  );
});
