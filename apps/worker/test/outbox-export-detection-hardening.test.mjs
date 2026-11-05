import assert from 'node:assert/strict';
import { test } from 'node:test';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import * as net from 'node:net';
import { randomUUID } from 'node:crypto';
import { cleanExpiredExportJobs } from '../dist/export-cleanup-job.js';
import { processOutboxBatch } from '../dist/notification-outbox-job.js';
import { runDetectionCycle } from '../dist/security-detection-job.js';

test('[CRIT-08] cleanExpiredExportJobs — unlinks valid files, cleans ENOENT, and preserves DB rows on out-of-bounds or non-regular files', async () => {
  const tempBase = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-export-test-'));
  const validFile = path.join(tempBase, 'export-valid.csv');
  const nestedDir = path.join(tempBase, 'subdir-not-a-file');
  const outsideFile = path.join(os.tmpdir(), `outside-${randomUUID()}.csv`);

  await fsp.writeFile(validFile, 'id,action\n1,TEST\n', 'utf8');
  await fsp.mkdir(nestedDir);
  await fsp.writeFile(outsideFile, 'do-not-delete', 'utf8');

  try {
    const jobs = [
      { id: 'job-valid', file_path: validFile },
      { id: 'job-enoent', file_path: path.join(tempBase, 'already-gone.csv') },
      { id: 'job-outside', file_path: outsideFile },
      { id: 'job-dir', file_path: nestedDir },
    ];
    const deletedJobIds = [];

    const mockDb = {
      asyncExportJob: {
        findMany: async () => jobs,
        delete: async ({ where }) => {
          deletedJobIds.push(where.id);
          return { id: where.id };
        },
      },
    };

    const prevExportDir = process.env['EXPORT_STORAGE_DIR'];
    process.env['EXPORT_STORAGE_DIR'] = tempBase;
    try {
      const result = await cleanExpiredExportJobs({ databaseClient: mockDb });
      assert.equal(result.filesDeleted, 1);
      assert.equal(result.expiredJobsCleaned, 2);
      assert.deepEqual(deletedJobIds, ['job-valid', 'job-enoent']);
    } finally {
      if (prevExportDir === undefined) delete process.env['EXPORT_STORAGE_DIR'];
      else process.env['EXPORT_STORAGE_DIR'] = prevExportDir;
    }

    const outsideStillExists = await fsp
      .stat(outsideFile)
      .then(() => true)
      .catch(() => false);
    assert.equal(outsideStillExists, true);
  } finally {
    await fsp.rm(outsideFile, { force: true });
    await fsp.rm(tempBase, { recursive: true, force: true });
  }
});

test('[HIGH-14] processOutboxBatch — claims via FOR UPDATE SKIP LOCKED, fails honestly when SMTP_HOST missing, and delivers via real SMTP', async () => {
  const prevHost = process.env['SMTP_HOST'];
  const prevPort = process.env['SMTP_PORT'];
  delete process.env['SMTP_HOST'];

  const itemMissingSmtp = {
    id: randomUUID(),
    recipient_id: 42n,
    channel: 'EMAIL',
    notification_type: 'SECURITY_ALERT',
    title: 'Critical Alert',
    body: 'Body content',
    payload: { email: 'sec@sda.internal' },
    status: 'PENDING',
    attempt_count: 0,
    max_attempts: 3,
    last_error: null,
    created_at: new Date(),
  };

  let rawClaimQuery = '';
  const mockDbNoSmtp = {
    $queryRawUnsafe: async (sql) => {
      rawClaimQuery = sql;
      return [itemMissingSmtp];
    },
    notificationOutbox: {
      update: async ({ data }) => Object.assign(itemMissingSmtp, data),
    },
  };

  const failRes = await processOutboxBatch({ databaseClient: mockDbNoSmtp });
  assert.match(rawClaimQuery, /FOR UPDATE SKIP LOCKED/u);
  assert.match(rawClaimQuery, /SET status = 'PROCESSING'/u);
  assert.equal(failRes.sent, 0);
  assert.equal(failRes.failed, 1);
  assert.equal(itemMissingSmtp.status, 'FAILED');
  assert.match(itemMissingSmtp.last_error, /missing SMTP_HOST/u);

  const receivedSmtpData = [];
  const smtpServer = net.createServer((socket) => {
    let inDataMode = false;
    let buf = '';
    socket.write('220 localhost ESMTP SDA-Test\r\n');
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      while (buf.includes('\r\n')) {
        if (inDataMode) {
          const endIdx = buf.indexOf('\r\n.\r\n');
          if (endIdx === -1) break;
          receivedSmtpData.push(buf.slice(0, endIdx));
          buf = buf.slice(endIdx + 5);
          inDataMode = false;
          socket.write('250 2.0.0 Queued\r\n');
          continue;
        }
        const idx = buf.indexOf('\r\n');
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const upper = line.toUpperCase();
        if (upper.startsWith('EHLO') || upper.startsWith('HELO')) {
          socket.write('250-localhost\r\n250 SIZE 1048576\r\n');
        } else if (upper.startsWith('MAIL FROM') || upper.startsWith('RCPT TO')) {
          socket.write('250 2.1.0 OK\r\n');
        } else if (upper === 'DATA') {
          inDataMode = true;
          socket.write('354 Start mail input\r\n');
        } else if (upper === 'QUIT') {
          socket.write('221 2.0.0 Bye\r\n');
          socket.end();
        } else {
          socket.write('250 OK\r\n');
        }
      }
    });
  });

  await new Promise((resolve) => smtpServer.listen(0, '127.0.0.1', resolve));
  const smtpPort = smtpServer.address().port;

  try {
    process.env['SMTP_HOST'] = '127.0.0.1';
    process.env['SMTP_PORT'] = String(smtpPort);

    const itemRealSmtp = {
      id: randomUUID(),
      recipient_id: 55n,
      channel: 'EMAIL',
      notification_type: 'SECURITY_ALERT',
      title: 'Alert Subject\r\nBcc: attacker@evil.test',
      body: 'Verified real SMTP body payload.',
      payload: {},
      status: 'PENDING',
      attempt_count: 0,
      max_attempts: 3,
      last_error: null,
      created_at: new Date(),
    };

    const mockDbSmtp = {
      $queryRawUnsafe: async () => [itemRealSmtp],
      user: {
        findUnique: async () => ({ email: 'officer@sda.internal' }),
      },
      notificationOutbox: {
        update: async ({ data }) => Object.assign(itemRealSmtp, data),
      },
    };

    const okRes = await processOutboxBatch({ databaseClient: mockDbSmtp });
    assert.equal(okRes.sent, 1);
    assert.equal(itemRealSmtp.status, 'SENT');
    assert.equal(receivedSmtpData.length, 1);
    assert.ok(!receivedSmtpData[0].includes('\r\nBcc: attacker@evil.test'));
    assert.ok(receivedSmtpData[0].includes('Verified real SMTP body payload.'));
  } finally {
    if (prevHost === undefined) delete process.env['SMTP_HOST'];
    else process.env['SMTP_HOST'] = prevHost;
    if (prevPort === undefined) delete process.env['SMTP_PORT'];
    else process.env['SMTP_PORT'] = prevPort;
    await new Promise((resolve) => smtpServer.close(resolve));
  }
});

test('[HIGH-16] runDetectionCycle — isolates per-user and anonymous cooldowns for UNTRUSTED_CONTEXT and REFRESH_TOKEN_REUSE', async () => {
  const now = new Date('2026-10-10T10:00:00Z');
  const createdAlerts = [];
  const mockDb = {
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'UNTRUSTED_CONTEXT',
          name: 'Untrusted Context',
          is_enabled: true,
          severity: 'HIGH',
          threshold: 1,
          window_minutes: 5,
          cooldown_minutes: 30,
          parameters: {},
        },
        {
          rule_code: 'REFRESH_TOKEN_REUSE',
          name: 'Refresh Reuse',
          is_enabled: true,
          severity: 'HIGH',
          threshold: 1,
          window_minutes: 5,
          cooldown_minutes: 15,
          parameters: {},
        },
      ],
    },
    auditLog: {
      findMany: async ({ where }) => {
        if (Array.isArray(where?.OR)) {
          return [
            {
              id: 1n,
              actor_user_id: 101n,
              action: 'LOGIN_SUCCESS',
              details: { untrustedIp: true },
              occurred_at: now,
            },
            {
              id: 2n,
              actor_user_id: 202n,
              action: 'LOGIN_SUCCESS',
              details: { untrustedDevice: true },
              occurred_at: now,
            },
            {
              id: 3n,
              actor_user_id: null,
              action: 'ACCESS_DENIED_UNTRUSTED_IP',
              details: {},
              occurred_at: now,
            },
          ];
        }
        return [
          { id: 4n, actor_user_id: 101n, occurred_at: now },
          { id: 5n, actor_user_id: 202n, occurred_at: now },
        ];
      },
    },
    securityAlert: {
      findFirst: async ({ where }) => {
        // Simulate User 101 already having an active cooldown alert, while User 202 and anonymous do NOT
        if (where.detected_user_id === 101n) return { id: 'existing-101' };
        return null;
      },
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => ({ count: data.length }),
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const result = await runDetectionCycle({ databaseClient: mockDb, now });
  assert.equal(result.alertsCreated, 3);
  assert.deepEqual(
    createdAlerts.map((a) => ({ type: a.alert_type, user: a.detected_user_id })),
    [
      { type: 'UNTRUSTED_CONTEXT', user: 202n },
      { type: 'UNTRUSTED_CONTEXT', user: null },
      { type: 'REFRESH_TOKEN_REUSE', user: 202n },
    ],
  );
});
