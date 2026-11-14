/**
 * @module OutboxDevMailSinkTest
 * Thuật toán kiểm thử: Đảm bảo hàng đợi `notification_outbox` lưu tệp `.eml` (`0o600`) vào `.local/mail-sink`
 * khi chạy ở môi trường `development` với `SMTP_HOST=127.0.0.1` không bật Mailpit (tránh dồn `DEAD_LETTER`),
 * đồng thời giữ nguyên cơ chế ném lỗi trung thực trên môi trường `production`.
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { processOutboxBatch } from '../dist/notification-outbox-job.js';

test('processOutboxBatch — spools .eml to dev mail-sink on loopback ECONNREFUSED in development and fails closed in production', async () => {
  const tempSink = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-worker-mailsink-'));
  const savedEnv = {
    NODE_ENV: process.env['NODE_ENV'],
    SMTP_HOST: process.env['SMTP_HOST'],
    SMTP_PORT: process.env['SMTP_PORT'],
    SDA_ENABLE_DEV_FALLBACK_IN_TEST: process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'],
    SDA_DEV_MAIL_SINK_DIR: process.env['SDA_DEV_MAIL_SINK_DIR'],
  };

  try {
    process.env['NODE_ENV'] = 'development';
    process.env['SMTP_HOST'] = '127.0.0.1';
    process.env['SMTP_PORT'] = '59996';
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] = 'true';
    process.env['SDA_DEV_MAIL_SINK_DIR'] = tempSink;

    const devItem = {
      id: randomUUID(),
      recipient_id: 101n,
      channel: 'EMAIL',
      notification_type: 'SECURITY_ALERT',
      title: 'Dev Loopback Alert\r\nBcc: spoof@evil.test',
      body: 'Outbox email spooled cleanly without Mailpit container.',
      payload: { email: 'security.demo@sda.internal' },
      status: 'PENDING',
      attempt_count: 0,
      max_attempts: 3,
      last_error: null,
      created_at: new Date(),
    };

    const devDb = {
      $queryRawUnsafe: async () => [devItem],
      notificationOutbox: {
        update: async ({ data }) => Object.assign(devItem, data),
      },
    };

    const devRes = await processOutboxBatch({ databaseClient: devDb });
    assert.equal(devRes.sent, 1);
    assert.equal(devItem.status, 'SENT');

    const files = await fsp.readdir(tempSink);
    assert.equal(files.length, 1);
    const emlText = await fsp.readFile(path.join(tempSink, files[0]), 'utf8');
    assert.match(emlText, /To: security\.demo@sda\.internal/u);
    assert.ok(!emlText.includes('\r\nBcc: spoof@evil.test'));

    process.env['NODE_ENV'] = 'production';
    const prodItem = { ...devItem, id: randomUUID(), status: 'PENDING', attempt_count: 0 };
    const prodDb = {
      $queryRawUnsafe: async () => [prodItem],
      notificationOutbox: {
        update: async ({ data }) => Object.assign(prodItem, data),
      },
    };
    const prodRes = await processOutboxBatch({ databaseClient: prodDb });
    assert.equal(prodRes.sent, 0);
    assert.equal(prodRes.failed, 1);
    assert.equal(prodItem.status, 'FAILED');
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await fsp.rm(tempSink, { recursive: true, force: true });
  }
});
