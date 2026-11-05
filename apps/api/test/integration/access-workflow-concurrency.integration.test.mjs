import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';
import { setupAccessWorkflowIntegrationFixture } from '../helpers/access-workflow-integration-setup.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_access_wf', { coerceBigIntId: true });
const ctx = { ip: '10.0.10.25', userAgent: 'integration-access', correlationId: randomUUID() };

let requestsService;
let grantsService;
let sessionsService;
let redlockService;
let ownerUser;
let readerUser;
let docId;
let versionId;

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  ({
    requestsService,
    grantsService,
    sessionsService,
    redlockService,
    ownerUser,
    readerUser,
    docId,
    versionId,
  } = await setupAccessWorkflowIntegrationFixture(dbHarness));
});

after(async () => {
  await redlockService?.onModuleDestroy();
  await dbHarness.teardown();
});

test('Access workflow SQL integration — request submission, Redlock-serialized approval, interval coalescing, session termination & notification outbox', async () => {
  const readerPrincipal = {
    userId: readerUser.id,
    sessionId: randomUUID(),
    username: 'reader.wf',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  const ownerPrincipal = {
    userId: ownerUser.id,
    sessionId: randomUUID(),
    username: 'owner.wf',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  const createdReq = await requestsService.createRequest(
    {
      documentId: docId,
      requestedAction: 'VIEW',
      reason: 'Cần nghiên cứu quy trình vận hành phục vụ đợt diễn tập an toàn Quý 4.',
      requestedUntil: new Date(Date.now() + 3 * 86_400_000).toISOString(),
    },
    readerPrincipal,
    ctx,
  );
  assert.equal(createdReq.status, 'PENDING');

  // Concurrent owner approvals serialized via Redlock + SQL transaction -> exactly one winner
  const settled = await Promise.allSettled([
    requestsService.decideRequest(
      createdReq.id,
      { decision: 'APPROVED', validDays: 5, decisionNote: 'Đồng ý cấp quyền đọc' },
      ownerPrincipal,
      ctx,
    ),
    requestsService.decideRequest(
      createdReq.id,
      { decision: 'APPROVED', validDays: 5, decisionNote: 'Đồng ý song song' },
      ownerPrincipal,
      ctx,
    ),
  ]);
  const reasons = settled
    .filter((r) => r.status === 'rejected')
    .map((r) => r.reason?.stack || r.reason?.message || String(r.reason));
  assert.equal(
    settled.filter((r) => r.status === 'fulfilled').length,
    1,
    `Expected 1 fulfilled decision, got rejections: ${reasons.join(' | ')}`,
  );
  assert.equal(settled.filter((r) => r.status === 'rejected').length, 1);

  // Verify ACCESS_GRANT_ISSUED notification & outbox persisted in SQL
  const issuedNotif = await dbHarness.sql.query(
    "SELECT count(*)::int AS cnt FROM notifications WHERE recipient_id=$1 AND notification_type='ACCESS_GRANT_ISSUED'",
    [readerUser.id],
  );
  assert.equal(issuedNotif.rows[0].cnt, 1);

  // Direct overlapping grant with same permission set coalesces into the single ACTIVE grant instead of duplicating
  const coalesced = await grantsService.createGrant(
    {
      documentId: docId,
      principalType: 'USER',
      principalUserId: readerUser.id,
      permissions: ['VIEW'],
      validUntil: new Date(Date.now() + 10 * 86_400_000).toISOString(),
    },
    ownerPrincipal,
    ctx,
  );
  const activeGrantsInSql = await dbHarness.sql.query(
    "SELECT count(*)::int AS cnt FROM access_grants WHERE document_id=$1 AND principal_user_id=$2 AND status='ACTIVE'",
    [docId, readerUser.id],
  );
  assert.equal(activeGrantsInSql.rows[0].cnt, 1);

  // Create two active sessions: terminate one manually via AccessSessionsService, cascade-terminate the other via revokeGrant
  const manualSessId = randomUUID();
  const cascadeSessId = randomUUID();
  await dbHarness.sql.query(
    `INSERT INTO access_sessions(id,access_grant_id,document_version_id,user_id,ip_address,status)
     VALUES ($1,$3,$4,$5,'10.0.10.50','ACTIVE'),($2,$3,$4,$5,'10.0.10.51','ACTIVE')`,
    [manualSessId, cascadeSessId, coalesced.id, versionId, readerUser.id],
  );

  // MEDIUM-04: invalid UUID throws 400 BadRequestException; valid termination writes audit log
  await assert.rejects(
    () => sessionsService.terminateSession('not-a-uuid', 'Bad ID', ownerPrincipal, ctx),
    BadRequestException,
  );
  const manualTerminated = await sessionsService.terminateSession(
    manualSessId,
    'Chấm dứt kiểm tra định kỳ',
    ownerPrincipal,
    ctx,
  );
  assert.equal(manualTerminated.status, 'TERMINATED');
  const terminatedListing = await sessionsService.listSessions({ status: 'TERMINATED' });
  assert.equal(terminatedListing.data[0].documentVersionId, String(versionId));

  // Revoke grant -> cascades to remaining active session and emits ACCESS_GRANT_REVOKED notification
  const revoked = await grantsService.revokeGrant(
    coalesced.id,
    { reason: 'Thu hồi sau khi kết thúc diễn tập' },
    ownerPrincipal,
    ctx,
  );
  assert.equal(revoked.status, 'REVOKED');

  const cascadeCheck = await dbHarness.sql.query(
    `SELECT
       (SELECT status::text FROM access_sessions WHERE id=$1) AS sess_status,
       (SELECT count(*)::int FROM notifications WHERE recipient_id=$2 AND notification_type='ACCESS_GRANT_REVOKED') AS revoke_notifs`,
    [cascadeSessId, readerUser.id],
  );
  assert.equal(cascadeCheck.rows[0].sess_status, 'TERMINATED');
  assert.equal(cascadeCheck.rows[0].revoke_notifs, 1);

  await assert.rejects(
    () =>
      grantsService.assertGrantValidForAccess(
        coalesced.id,
        readerUser.id,
        'VIEW',
        new Date(),
        docId,
      ),
    (err) => err.response?.errorCode === AppErrorCode.GRANT_REVOKED,
  );
});
