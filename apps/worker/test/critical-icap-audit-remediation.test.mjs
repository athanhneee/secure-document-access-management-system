import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import * as net from 'node:net';
import { gzipSync } from 'node:zlib';
import { test } from 'node:test';
import { DlpEngine } from '../dist/icap/dlp-engine.js';
import { IcapServer } from '../dist/icap/icap-server.js';
import { runAuditVerificationSweep } from '../dist/audit-verification-job.js';

process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.NODE_ENV = 'test';

test('[CRIT-03 & CRIT-04] IcapServer blocks split-TCP Preview: 0 + chunk-extension + gzip Vietnamese secret payload', async () => {
  const server = new IcapServer({
    enabled: true,
    port: 0,
    host: '127.0.0.1',
    action: 'BLOCK',
  });
  const { port } = await server.start();

  try {
    const httpHeaders =
      'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Encoding: gzip\r\n\r\n';
    const icapHeaders =
      `RESPMOD icap://127.0.0.1:${port}/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1:${port}\r\n` +
      `Preview: 0\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(httpHeaders)}\r\n\r\n` +
      httpHeaders;

    const compressedLeak = gzipSync(
      Buffer.from('Hồ sơ tác chiến MẬT QUÂN SỰ không được phép gửi ra ngoài!', 'utf8'),
    );
    const bodyWithChunkExt = Buffer.concat([
      Buffer.from(`${compressedLeak.length.toString(16)};ext=trace1\r\n`, 'ascii'),
      compressedLeak,
      Buffer.from('\r\n0\r\n\r\n', 'ascii'),
    ]);

    const finalResponse = await new Promise((resolve, reject) => {
      const guard = setTimeout(
        () => reject(new Error('ICAP Preview: 0 handshake timed out')),
        3000,
      );
      let received = '';
      let sentPreviewTerminator = false;
      let sentRealBody = false;

      const socket = net.createConnection({ host: '127.0.0.1', port }, async () => {
        // Packet 1: headers ONLY (without 0\r\n\r\n preview terminator yet)
        socket.write(Buffer.from(icapHeaders, 'utf8'));
        await new Promise((r) => setTimeout(r, 30));
        assert.equal(
          received.includes('100 Continue'),
          false,
          'Server must wait for 0\\r\\n\\r\\n preview chunk before sending 100 Continue',
        );
        // Packet 2: preview zero-length chunk terminator
        sentPreviewTerminator = true;
        socket.write(Buffer.from('0\r\n\r\n', 'ascii'));
      });

      socket.on('data', (chunk) => {
        received += chunk.toString('utf8');
        if (sentPreviewTerminator && !sentRealBody && received.includes('ICAP/1.0 100 Continue')) {
          sentRealBody = true;
          // Packet 3: real post-Continue gzipped body with RFC 2616 chunk extension
          socket.write(bodyWithChunkExt);
        }
      });

      socket.on('end', () => {
        clearTimeout(guard);
        resolve(received);
      });
      socket.on('error', (err) => {
        clearTimeout(guard);
        reject(err);
      });
    });

    assert.equal(
      finalResponse.includes('ICAP/1.0 204 No modifications'),
      false,
      'Must NOT prematurely return 204 on Preview: 0 terminator chunk',
    );
    assert.ok(finalResponse.includes('ICAP/1.0 100 Continue'));
    assert.ok(finalResponse.includes('HTTP/1.1 403 Forbidden'));
    assert.ok(finalResponse.includes('X-DLP-Status: BLOCKED'));
  } finally {
    await server.stop();
  }
});

test('[CRIT-04] DlpEngine catches Vietnamese diacritic boundaries (Ự, Ộ), zero-width chars, and NFKC fullwidth', () => {
  for (const sample of [
    'Đính kèm công văn MẬT QUÂN SỰ.',
    'Quy chế BÍ MẬT NỘI BỘ!',
    'Trích sao M\u200BẬT QUÂN S\u200DỰ khẩn.',
    'Hồ sơ ＴＵＹỆＴ ＭẬＴ cấp chiến lược',
  ]) {
    const res = DlpEngine.scanPayload(Buffer.from(sample, 'utf8'));
    assert.equal(res.isClean, false, `Expected DLP block for sample: ${sample}`);
    assert.equal(res.action, 'BLOCK');
  }
});

test('[CRIT-01 & CRIT-02] Worker audit sweep detects head truncation and never leaks HMAC oracle in security_alerts', async () => {
  const secretKey = 'worker-audit-hmac-secret-key-at-least-32-bytes!!';
  const occurredAt = new Date('2026-10-10T08:00:00.000Z');
  const corrId = randomUUID();

  const canonicalPayload = JSON.stringify({
    accessSessionId: null,
    action: 'USER_LOGIN',
    actorUserId: '1',
    actorUsername: 'alice',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: 'AUTH',
    chainSequence: '1',
    correlationId: corrId,
    details: {},
    documentId: null,
    ipAddress: '127.0.0.1',
    objectId: '1',
    objectType: 'AUTHENTICATION',
    occurredAt: occurredAt.toISOString(),
    outcome: 'SUCCESS',
    previousHash: null,
    reasonCode: null,
    userAgent: null,
  });
  const realHmac = createHmac('sha256', secretKey).update(canonicalPayload, 'utf8').digest('hex');

  const truncatedHeadRow = {
    id: 5n,
    chain_partition: 'AUTH',
    chain_sequence: 5n, // Head rows 1..4 deleted!
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    action: 'USER_LOGIN',
    actor_user_id: 1n,
    actor_username: 'alice',
    correlation_id: corrId,
    details: {},
    document_id: null,
    access_session_id: null,
    ip_address: '127.0.0.1',
    object_type: 'AUTHENTICATION',
    object_id: '1',
    occurred_at: occurredAt,
    outcome: 'SUCCESS',
    previous_hash: 'a'.repeat(64),
    reasonCode: null,
    reason_code: null,
    user_agent: null,
    entry_hash: '0'.repeat(64), // Tampered row 1..N
  };

  const createdAlerts = [];
  const mockDb = {
    auditLog: {
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        if (args?.where?.chain_sequence?.gt === 5n) return [];
        return [truncatedHeadRow];
      },
    },
    auditAnchor: {
      findMany: async () => [],
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        createdAlerts.push(data);
        return { id: 99n, ...data };
      },
    },
    alertAuditLink: {
      create: async ({ data }) => data,
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const summary = await runAuditVerificationSweep(secretKey, { databaseClient: mockDb });
  assert.ok(summary.totalViolations >= 1, 'Head truncation and tampering must report violations');
  assert.equal(createdAlerts.length, 1);
  const serializedAlert = JSON.stringify(createdAlerts[0]);
  assert.equal(
    serializedAlert.includes('"expected"'),
    false,
    'Alert description must never include expected HMAC signing oracle field',
  );
  assert.equal(
    serializedAlert.includes(realHmac),
    false,
    'Alert description must never leak computed HMAC digest',
  );
});
