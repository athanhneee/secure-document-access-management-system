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
import { extractOfficeFallbackText } from '../dist/modules/documents/office-ooxml-extractor.helper.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import {
  isWindowsDefenderCliAvailable,
  scanBufferWithWindowsDefender,
} from '../dist/modules/documents/windows-defender-scanner.helper.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

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

test('OfficeOoxmlExtractorHelper & OfficeConverterService — preserve DOCX tables and XLSX worksheet grids in PDF fallback', async () => {
  const docxWithTable = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Executive Summary</w:t></w:r></w:p>' +
        '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Department</w:t></w:r></w:p></w:tc>' +
        '<w:tc><w:p><w:r><w:t>Clearance</w:t></w:r></w:p></w:tc></w:tr>' +
        '<w:tr><w:tc><w:p><w:r><w:t>SOC</w:t></w:r></w:p></w:tc>' +
        '<w:tc><w:p><w:r><w:t>TOP_SECRET</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>',
    },
  ]);
  const docxText = await extractOfficeFallbackText(docxWithTable, 'summary.docx');
  assert.match(docxText, /\| Department \| Clearance \|/u);
  assert.match(docxText, /\| SOC \| TOP_SECRET \|/u);

  const xlsxWorkbook = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'xl/sharedStrings.xml',
      content: '<sst><si><t>Metric</t></si><si><t>Score</t></si></sst>',
    },
    {
      name: 'xl/worksheets/sheet1.xml',
      content:
        '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>' +
        '<row r="2"><c r="A2" t="inlineStr"><is><t>Audit</t></is></c><c r="B2"><v>100</v></c></row></sheetData></worksheet>',
    },
  ]);
  const xlsxText = await extractOfficeFallbackText(xlsxWorkbook, 'metrics.xlsx');
  assert.match(xlsxText, /\| Metric \| Score \|/u);
  assert.match(xlsxText, /\| Audit \| 100 \|/u);

  const converter = new OfficeConverterService();
  const pdf = await converter.convertOfficeToPdf(xlsxWorkbook, 'metrics.xlsx');
  assert.equal(pdf.subarray(0, 4).toString('ascii'), '%PDF');
});
