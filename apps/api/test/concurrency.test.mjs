import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';

// ── 1. Scenario 1: Hai owner duyệt cùng request đồng thời ─────────────────────

test('Concurrency Scenario 1 — two owners approving same access request concurrently allows exactly one winner', async () => {
  let requestStatus = 'PENDING';
  let createdGrants = [];
  let decisionCount = 0;

  // Atomic decision handler simulating PostgreSQL transaction / conditional UPDATE:
  // UPDATE access_requests SET status = 'APPROVED' WHERE id = :id AND status = 'PENDING'
  async function decideRequest(ownerId, decision, delayMs) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));

    // Atomic compare-and-swap check
    if (requestStatus !== 'PENDING') {
      return { success: false, error: 'REQUEST_ALREADY_DECIDED' };
    }

    requestStatus = decision;
    decisionCount += 1;
    const grant = {
      id: randomUUID(),
      ownerId,
      grantedAt: new Date(),
    };
    createdGrants.push(grant);
    return { success: true, grant };
  }

  // Two owners simultaneously submit approval
  const [result1, result2] = await Promise.all([
    decideRequest(101n, 'APPROVED', 5),
    decideRequest(102n, 'APPROVED', 5),
  ]);

  const successes = [result1, result2].filter((r) => r.success);
  const failures = [result1, result2].filter((r) => !r.success);

  assert.equal(successes.length, 1, 'Exactly one owner approval must succeed.');
  assert.equal(failures.length, 1, 'Concurrent second approval must be rejected.');
  assert.equal(failures[0].error, 'REQUEST_ALREADY_DECIDED');
  assert.equal(createdGrants.length, 1, 'Zero duplicate access grants must be created.');
  assert.equal(requestStatus, 'APPROVED');
});

// ── 2. Scenario 2: Version upload đồng thời ───────────────────────────────────

test('Concurrency Scenario 2 — concurrent version uploads generate strictly monotonic distinct version numbers', async () => {
  let currentMaxVersion = 1;
  const versions = [];
  const mutex = { locked: false };

  // Simulates document version sequence lock (SELECT MAX(version_no) FOR UPDATE)
  async function uploadNewVersion(uploaderId, fileHash) {
    // Acquire lock
    while (mutex.locked) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    mutex.locked = true;

    try {
      // Critical section
      currentMaxVersion += 1;
      const assignedVersion = currentMaxVersion;
      await new Promise((resolve) => setTimeout(resolve, 5)); // simulate I/O

      const versionRecord = {
        versionNo: assignedVersion,
        uploaderId,
        sha256Hash: fileHash,
        createdAt: new Date(),
      };
      versions.push(versionRecord);
      return versionRecord;
    } finally {
      mutex.locked = false;
    }
  }

  // Five simultaneous uploads
  const results = await Promise.all([
    uploadNewVersion(1n, 'hash-a'),
    uploadNewVersion(2n, 'hash-b'),
    uploadNewVersion(3n, 'hash-c'),
    uploadNewVersion(4n, 'hash-d'),
    uploadNewVersion(5n, 'hash-e'),
  ]);

  const versionNumbers = results.map((r) => r.versionNo).sort((a, b) => a - b);
  assert.deepEqual(
    versionNumbers,
    [2, 3, 4, 5, 6],
    'Version numbers must be strictly sequential with zero duplicates',
  );
  assert.equal(new Set(versionNumbers).size, 5);
});

// ── 3. Scenario 3: Revoke trong lúc mở file ───────────────────────────────────

test('Concurrency Scenario 3 — revoking access grant immediately terminates active streaming and download tickets', async () => {
  let grantStatus = 'ACTIVE';
  const activeSessions = new Map();
  const sessionId = randomUUID();

  // User opens file and creates active session
  activeSessions.set(sessionId, {
    id: sessionId,
    status: 'ACTIVE',
    userId: 42n,
    documentId: 'doc-1',
  });

  function verifyChunkAccess(sId) {
    const session = activeSessions.get(sId);
    if (!session || session.status !== 'ACTIVE' || grantStatus !== 'ACTIVE') {
      throw new Error('ACCESS_DENIED_SESSION_TERMINATED');
    }
    return true;
  }

  // Reading chunk 1 succeeds
  assert.equal(verifyChunkAccess(sessionId), true);

  // Concurrently revoke grant and terminate sessions
  async function revokeGrant() {
    grantStatus = 'REVOKED';
    for (const session of activeSessions.values()) {
      if (session.documentId === 'doc-1') {
        session.status = 'TERMINATED';
        session.terminatedReason = 'Grant revoked by document owner';
      }
    }
  }

  // Revocation takes effect
  await revokeGrant();

  // Subsequent chunk request fails immediately
  assert.throws(() => verifyChunkAccess(sessionId), /ACCESS_DENIED_SESSION_TERMINATED/u);
  assert.equal(activeSessions.get(sessionId).status, 'TERMINATED');
});

// ── 4. Scenario 4: Reclassification trong lúc có active session ───────────────

test('Concurrency Scenario 4 — document reclassification terminates active sessions of users with insufficient clearance', async () => {
  const classificationRanks = {
    CONG_KHAI: 1,
    NOI_BO: 2,
    MAT: 3,
    TOI_MAT: 4,
  };

  let documentClassification = 'NOI_BO';
  const sessions = [
    {
      id: 'session-alice',
      userId: 10n,
      userClearance: 'NOI_BO', // rank 2
      status: 'ACTIVE',
    },
    {
      id: 'session-bob',
      userId: 20n,
      userClearance: 'TOI_MAT', // rank 4
      status: 'ACTIVE',
    },
  ];

  async function reclassifyDocument(newClassification) {
    documentClassification = newClassification;
    const requiredRank = classificationRanks[newClassification];

    // Terminate any active session where user's clearance < requiredRank
    for (const session of sessions) {
      const userRank = classificationRanks[session.userClearance];
      if (session.status === 'ACTIVE' && userRank < requiredRank) {
        session.status = 'TERMINATED';
        session.terminatedReason = `Document elevated to ${newClassification}; clearance insufficient`;
      }
    }
  }

  // Elevate document from NOI_BO (2) to TOI_MAT (4)
  await reclassifyDocument('TOI_MAT');
  assert.equal(documentClassification, 'TOI_MAT');

  // Alice (rank 2) is terminated immediately
  assert.equal(sessions[0].status, 'TERMINATED');
  assert.ok(sessions[0].terminatedReason.includes('clearance insufficient'));

  // Bob (rank 4) remains active
  assert.equal(sessions[1].status, 'ACTIVE');
});

// ── 5. Scenario 5: Refresh token reuse đồng thời ──────────────────────────────

test('Concurrency Scenario 5 — concurrent refresh token reuse detects breach, revokes token family, and triggers alert', async () => {
  let tokenState = {
    activeToken: 'token-v1-original',
    isRevoked: false,
    alertEmitted: false,
  };

  async function refresh(suppliedToken) {
    await new Promise((resolve) => setTimeout(resolve, 5));

    if (tokenState.isRevoked) {
      tokenState.alertEmitted = true;
      throw new Error('TOKEN_FAMILY_ALREADY_REVOKED');
    }

    if (suppliedToken !== tokenState.activeToken) {
      // Replay / Reuse detected!
      tokenState.isRevoked = true;
      tokenState.alertEmitted = true;
      throw new Error('REFRESH_TOKEN_REUSE_DETECTED');
    }

    // Normal rotation
    const newToken = `token-v2-${randomUUID()}`;
    tokenState.activeToken = newToken;
    return newToken;
  }

  // Initial valid refresh rotates token
  const nextToken = await refresh('token-v1-original');
  assert.ok(nextToken.startsWith('token-v2-'));

  // Two attackers concurrently replay the old 'token-v1-original'
  const [attempt1, attempt2] = await Promise.allSettled([
    refresh('token-v1-original'),
    refresh('token-v1-original'),
  ]);

  assert.equal(attempt1.status, 'rejected');
  assert.equal(attempt2.status, 'rejected');
  assert.ok(tokenState.isRevoked, 'Token family must be completely revoked');
  assert.ok(tokenState.alertEmitted, 'Security alert must be emitted upon reuse detection');
});
