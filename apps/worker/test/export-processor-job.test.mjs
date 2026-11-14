import assert from 'node:assert/strict';
import { createDecipheriv, createHash, hkdfSync, randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { formatExportPayload, sanitizeSpreadsheetCell } from '../dist/export-formatter.helper.js';
import { processPendingExportJobs } from '../dist/export-processor-job.js';

test('ExportFormatter — neutralizes spreadsheet formula injection and emits valid CSV, JSON, EXCEL XML, and %PDF-1.4', () => {
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
    assert.equal(
      safe.startsWith("'"),
      true,
      `Expected leading quote neutralization for: ${payload}`,
    );
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
  assert.equal(parsedJson.exportType, 'SECURITY_ALERTS');

  const excel = formatExportPayload('SECURITY_ALERTS', 'EXCEL', rows);
  const excelText = excel.buffer.toString('utf8');
  assert.ok(excelText.startsWith('<?xml version="1.0"'));
  assert.ok(excelText.includes('<Workbook'));
  assert.ok(excelText.includes('&apos;  =HYPERLINK'));
  assert.ok(excelText.includes('R&amp;D &lt;Alpha&gt;'));

  const pdf = formatExportPayload('SECURITY_ALERTS', 'PDF', rows);
  const pdfText = pdf.buffer.toString('latin1');
  assert.ok(pdfText.startsWith('%PDF-1.4\n'));
  assert.ok(pdfText.includes('\nxref\n'));
  assert.ok(pdfText.endsWith('%%EOF\n'));
});

test('ExportProcessorJob — claims PENDING job, enforces __allowedDepartmentIds scope, writes atomically with SHA-256', async () => {
  const exportDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-worker-export-'));
  const jobId = randomUUID();
  let capturedSecurityWhere = null;
  let completedUpdate = null;

  const pendingJob = {
    id: jobId,
    export_type: 'SECURITY_ALERTS',
    format: 'PDF',
    filter_params: {
      severity: 'HIGH',
      __allowedDepartmentIds: [10, 20],
    },
    status: 'PENDING',
  };

  const mockDb = {
    user: {
      findMany: async () => [{ id: 42n }],
    },
    document: {
      findMany: async () => [{ id: 'doc-10' }],
    },
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

  const prevAuditKey = process.env.AUDIT_INTEGRITY_KEY;
  process.env.AUDIT_INTEGRITY_KEY = 'worker-api-shared-export-integrity-key-32b!!';
  try {
    const result = await processPendingExportJobs({
      databaseClient: mockDb,
      exportBaseDir: exportDir,
    });

    assert.equal(result.completed, 1);
    assert.equal(result.failed, 0);
    assert.ok(
      Array.isArray(capturedSecurityWhere?.AND?.[1]?.OR),
      'Must enforce __allowedDepartmentIds scoped OR filter',
    );
    assert.ok(completedUpdate);
    assert.equal(completedUpdate.status, 'COMPLETED');
    assert.equal(completedUpdate.row_count, 1);

    const writtenBytes = await fsp.readFile(completedUpdate.file_path);
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
    assert.equal(completedUpdate.file_size_bytes, BigInt(decryptedBytes.byteLength));
    assert.ok(decryptedBytes.toString('latin1').startsWith('%PDF-1.4\n'));
  } finally {
    if (prevAuditKey === undefined) delete process.env.AUDIT_INTEGRITY_KEY;
    else process.env.AUDIT_INTEGRITY_KEY = prevAuditKey;
    await fsp.rm(exportDir, { recursive: true, force: true });
  }
});
