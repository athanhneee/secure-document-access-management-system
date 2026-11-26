import assert from 'node:assert/strict';
import { createDecipheriv, createHash, hkdfSync, randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { inflateRawSync } from 'node:zlib';
import { formatExportPayload, sanitizeSpreadsheetCell } from '../dist/exports/export-formatter.js';
import { processPendingExportJobs } from '../dist/export-processor-job.js';

/**
 * Thuật toán: Giải nén các mục Local File Header (`0x04034b50`) trong gói ZIP OOXML `.xlsx` phục vụ kiểm thử đơn vị.
 */
function readZipXmlEntries(zipBuffer) {
  const entries = new Map();
  let offset = 0;
  while (offset + 30 <= zipBuffer.length && zipBuffer.readUInt32LE(offset) === 0x04034b50) {
    const compSize = zipBuffer.readUInt32LE(offset + 18);
    const nameLen = zipBuffer.readUInt16LE(offset + 26);
    const extraLen = zipBuffer.readUInt16LE(offset + 28);
    const name = zipBuffer.subarray(offset + 30, offset + 30 + nameLen).toString('utf8');
    const dataStart = offset + 30 + nameLen + extraLen;
    const inflated = inflateRawSync(zipBuffer.subarray(dataStart, dataStart + compSize));
    entries.set(name, inflated.toString('utf8'));
    offset = dataStart + compSize;
  }
  return entries;
}

test('ExportFormatter — neutralizes formula injection, emits standard OOXML .xlsx ZIP and multi-page %PDF-1.4 without 55-row cap', () => {
  for (const payload of [
    "=CMD|' /C calc'!A0",
    '  +SUM(A1:A2)',
    '\t-2+3',
    ' @IMPORTXML("http://evil")',
    '|/bin/sh',
    '\r=1+1',
    '\n@evil',
  ]) {
    const safe = sanitizeSpreadsheetCell(payload);
    assert.equal(safe.startsWith("'"), true, `Expected leading quote for: ${payload}`);
  }

  const rows = [
    {
      id: '101',
      title: '  =HYPERLINK("http://evil.example","Click")',
      severity: 'CRITICAL',
      department: 'R&D <Alpha>',
    },
  ];

  const csv = formatExportPayload('SECURITY_ALERTS', 'CSV', rows);
  assert.equal(csv.extension, 'csv');
  assert.ok(csv.buffer.toString('utf8').includes("'  =HYPERLINK"));

  const json = formatExportPayload('SECURITY_ALERTS', 'JSON', rows);
  const parsedJson = JSON.parse(json.buffer.toString('utf8'));
  assert.equal(parsedJson.rowCount, 1);

  const excel = formatExportPayload('SECURITY_ALERTS', 'EXCEL', rows);
  assert.equal(excel.extension, 'xlsx');
  assert.equal(excel.mimeType, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  assert.deepEqual(excel.buffer.subarray(0, 4), Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  const zipEntries = readZipXmlEntries(excel.buffer);
  assert.ok(zipEntries.has('[Content_Types].xml'));
  assert.ok(zipEntries.has('_rels/.rels'));
  assert.ok(zipEntries.has('xl/workbook.xml'));
  assert.ok(zipEntries.has('xl/_rels/workbook.xml.rels'));
  const sheetXml = zipEntries.get('xl/worksheets/sheet1.xml');
  assert.ok(sheetXml?.includes('t="inlineStr"'));
  assert.ok(sheetXml?.includes('&apos;  =HYPERLINK'));
  assert.ok(sheetXml?.includes('R&amp;D &lt;Alpha&gt;'));

  const manyRows = Array.from({ length: 95 }, (_, idx) => ({
    id: `row-${idx + 1}`,
    title: `Báo cáo kiểm toán dòng số ${idx + 1} - Đầy đủ dữ liệu`,
    severity: 'HIGH',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  }));
  const pdf = formatExportPayload('SECURITY_ALERTS', 'PDF', manyRows);
  const pdfText = pdf.buffer.toString('latin1');
  assert.ok(pdfText.startsWith('%PDF-1.4\n'));
  assert.ok(!pdfText.includes('additional row(s) omitted'));
  assert.ok(pdfText.includes('Page 1 of '));
  assert.ok(pdfText.includes('row-95 |'));
  assert.match(pdfText, /\/Count [3-9]/u);
  assert.ok(pdfText.includes('\nxref\n'));
  assert.ok(pdfText.endsWith('%%EOF\n'));
});

test('ExportProcessorJob — claims PENDING job, pushes AES-256-GCM .dat to S3/R2 and writes atomically with SHA-256', async () => {
  const exportDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-worker-export-'));
  const jobId = randomUUID();
  let capturedSecurityWhere = null;
  let completedUpdate = null;
  const s3Uploads = new Map();

  const s3Server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      s3Uploads.set((req.url ?? '').split('?')[0], Buffer.concat(chunks));
      res.writeHead(200, { ETag: '"worker-r2-etag"' });
      res.end();
    });
  });
  await new Promise((resolve) => s3Server.listen(0, '127.0.0.1', resolve));
  const s3Port = s3Server.address().port;

  const pendingJob = {
    id: jobId,
    export_type: 'SECURITY_ALERTS',
    format: 'EXCEL',
    filter_params: {
      severity: 'HIGH',
      __allowedDepartmentIds: [10, 20],
    },
    status: 'PENDING',
  };

  const mockDb = {
    user: { findMany: async () => [{ id: 42n }] },
    document: { findMany: async () => [{ id: 'doc-10' }] },
    asyncExportJob: {
      count: async () => 0,
      findMany: async () => [pendingJob],
      updateMany: async () => ({ count: 1 }),
      update: async ({ data }) => {
        completedUpdate = data;
        return { ...pendingJob, ...data };
      },
    },
    securityAlert: {
      findMany: async ({ where }) => {
        capturedSecurityWhere = where;
        return [
          {
            id: 'alert-1',
            detected_at: new Date('2026-11-12T09:00:00.000Z'),
            alert_type: 'UNUSUAL_DOWNLOAD_BURST',
            severity: 'HIGH',
            status: 'OPEN',
            title: 'Burst detected (dept 10)',
            detected_user_id: 42n,
            document_id: 'doc-10',
          },
        ];
      },
    },
  };

  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    STORAGE_MOCK: process.env.STORAGE_MOCK,
    STORAGE_ENDPOINT: process.env.STORAGE_ENDPOINT,
    STORAGE_ACCESS_KEY: process.env.STORAGE_ACCESS_KEY,
    STORAGE_SECRET_KEY: process.env.STORAGE_SECRET_KEY,
    STORAGE_BUCKET_DERIVATIVES: process.env.STORAGE_BUCKET_DERIVATIVES,
    AUDIT_INTEGRITY_KEY: process.env.AUDIT_INTEGRITY_KEY,
  };
  process.env.NODE_ENV = 'production';
  process.env.STORAGE_MOCK = 'false';
  process.env.STORAGE_ENDPOINT = `http://127.0.0.1:${s3Port}`;
  process.env.STORAGE_ACCESS_KEY = 'worker-s3-key';
  process.env.STORAGE_SECRET_KEY = 'worker-s3-secret';
  process.env.STORAGE_BUCKET_DERIVATIVES = 'sda-derivatives';
  process.env.AUDIT_INTEGRITY_KEY = 'worker-api-shared-export-integrity-key-32b!!';

  try {
    const result = await processPendingExportJobs({
      databaseClient: mockDb,
      exportBaseDir: exportDir,
    });

    assert.equal(result.completed, 1);
    assert.equal(result.failed, 0);
    assert.ok(Array.isArray(capturedSecurityWhere?.OR));
    assert.equal(completedUpdate.status, 'COMPLETED');
    assert.equal(
      completedUpdate.mime_type,
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    );

    const s3ObjectBytes = s3Uploads.get(`/sda-derivatives/exports/${jobId}.dat`);
    assert.ok(
      Buffer.isBuffer(s3ObjectBytes),
      'Must upload encrypted .dat to S3 derivatives bucket',
    );
    const writtenBytes = await fsp.readFile(completedUpdate.file_path);
    assert.deepEqual(s3ObjectBytes, writtenBytes);
    assert.ok(writtenBytes.subarray(0, 5).equals(Buffer.from('SDEA\x01', 'binary')));

    const key = Buffer.from(
      hkdfSync(
        'sha256',
        Buffer.from(process.env.AUDIT_INTEGRITY_KEY, 'utf8'),
        Buffer.from('sda-export-at-rest-salt-v1', 'utf8'),
        Buffer.from('sda-export-artifact-aes-256-gcm', 'utf8'),
        32,
      ),
    );
    const decipher = createDecipheriv('aes-256-gcm', key, writtenBytes.subarray(5, 17), {
      authTagLength: 16,
    });
    decipher.setAAD(Buffer.from(jobId, 'utf8'));
    decipher.setAuthTag(writtenBytes.subarray(17, 33));
    const decryptedBytes = Buffer.concat([
      decipher.update(writtenBytes.subarray(33)),
      decipher.final(),
    ]);
    const expectedSha = createHash('sha256').update(decryptedBytes).digest('hex');
    assert.equal(completedUpdate.sha256_hash, expectedSha);
    assert.deepEqual(decryptedBytes.subarray(0, 4), Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await new Promise((resolve) => s3Server.close(resolve));
    await fsp.rm(exportDir, { recursive: true, force: true });
  }
});
