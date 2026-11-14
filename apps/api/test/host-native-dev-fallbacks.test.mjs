/**
 * @module HostNativeDevFallbacksTest
 * Thuật toán kiểm thử: Xác minh các bộ thích ứng bản địa không cần Docker trên máy chủ phát triển (`ResetMailerService` `.eml` sink,
 * `WindowsDefenderScannerHelper`, `LocalLibreOfficeHelper`) hoạt động an toàn ở `development` và vẫn đóng chặt (Fail-Closed) ở `production`.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { AppConfigService } from '../dist/config/config.service.js';
import { ResetMailerService } from '../dist/modules/auth/reset-mailer.service.js';
import { convertWithLocalLibreOffice } from '../dist/modules/documents/local-libreoffice.helper.js';
import {
  isWindowsDefenderCliAvailable,
  scanBufferWithWindowsDefender,
} from '../dist/modules/documents/windows-defender-scanner.helper.js';

test('ResetMailerService — spools RFC-5322 .eml in development loopback offline mode and fails closed in production', async () => {
  const tempSink = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-api-mailsink-'));
  const prevEnv = {
    NODE_ENV: process.env['NODE_ENV'],
    SDA_ENABLE_DEV_FALLBACK_IN_TEST: process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'],
    SDA_DEV_MAIL_SINK_DIR: process.env['SDA_DEV_MAIL_SINK_DIR'],
  };

  try {
    process.env['NODE_ENV'] = 'development';
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] = 'true';
    process.env['SDA_DEV_MAIL_SINK_DIR'] = tempSink;

    const devConfig = new AppConfigService({
      NODE_ENV: 'development',
      SMTP_HOST: '127.0.0.1',
      SMTP_PORT: 59997,
      SMTP_FROM: 'no-reply@sda.internal',
      PASSWORD_RESET_BASE_URL: 'http://127.0.0.1:3200/reset-password',
    });
    const devMailer = new ResetMailerService(devConfig);
    await devMailer.send('reader.demo@sda.internal', 'tok_secret_one_time_123');

    const files = await fsp.readdir(tempSink);
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith('.eml'));
    const content = await fsp.readFile(path.join(tempSink, files[0]), 'utf8');
    assert.match(content, /To: reader\.demo@sda\.internal/u);
    assert.match(content, /token=tok_secret_one_time_123/u);

    process.env['NODE_ENV'] = 'production';
    await assert.rejects(() => devMailer.send('reader.demo@sda.internal', 'tok_prod_fail'));
  } finally {
    for (const [k, v] of Object.entries(prevEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await fsp.rm(tempSink, { recursive: true, force: true });
  }
});

test('WindowsDefenderScannerHelper & LocalLibreOfficeHelper — respect test/disable guards and execute safely on host', async () => {
  assert.equal(isWindowsDefenderCliAvailable(), false);
  const skipped = await scanBufferWithWindowsDefender(Buffer.from('%PDF-1.7\nclean'));
  assert.equal(skipped.executed, false);
  assert.equal(skipped.status, 'CLEAN');

  const prevFlag = process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'];
  const prevDisable = process.env['SDA_DISABLE_HOST_DEFENDER'];
  try {
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] = 'true';
    process.env['SDA_DISABLE_HOST_DEFENDER'] = 'true';
    assert.equal(isWindowsDefenderCliAvailable(), false);

    delete process.env['SDA_DISABLE_HOST_DEFENDER'];
    if (process.platform === 'win32') {
      const cleanOutcome = await scanBufferWithWindowsDefender(
        Buffer.from('%PDF-1.7\nsafe host scan verification\n%%EOF'),
      );
      assert.equal(cleanOutcome.status, 'CLEAN');
    }

    const loResult = await convertWithLocalLibreOffice(
      Buffer.from('not-an-office-zip'),
      'sample.docx',
      2_000,
    );
    assert.equal(loResult, null);
  } finally {
    if (prevFlag === undefined) delete process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'];
    else process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] = prevFlag;
    if (prevDisable === undefined) delete process.env['SDA_DISABLE_HOST_DEFENDER'];
    else process.env['SDA_DISABLE_HOST_DEFENDER'] = prevDisable;
  }
});
