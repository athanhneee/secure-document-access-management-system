import assert from 'node:assert/strict';
import { test } from 'node:test';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { createSamplePdfBuffer } from './helpers/zip-builder.mjs';
import { createIngestionHarness } from './helpers/document-ingestion-mocks.mjs';

test('DocumentIngestionService: streaming upload enforces file size limit and aborts immediately', async () => {
  const { ingestion, recordedAudits } = createIngestionHarness({
    configOverrides: { UPLOAD_MAX_FILE_SIZE_BYTES: 1024 },
  });

  const largeData = Buffer.alloc(2048, 'A');
  const stream = Readable.from([largeData]);

  const principal = {
    userId: 100n,
    sessionId: 'session-1',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  await assert.rejects(async () => {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'large_memo.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  }, /File size exceeds allowed limit/i);

  const failedAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_UPLOAD_FAILED');
  assert.ok(failedAudit);
  assert.equal(failedAudit.outcome, 'FAILED');
});

test('DocumentIngestionService: EICAR infected file is quarantined and NEVER becomes ACTIVE', async () => {
  const { ingestion, storage, recordedAudits } = createIngestionHarness();

  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const infectedData = Buffer.from(`%PDF-1.4\n${eicarString}\n%%EOF`);
  const stream = Readable.from([infectedData]);

  const principal = {
    userId: 101n,
    sessionId: 'session-2',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  await assert.rejects(async () => {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'infected_memo.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  }, /Malware detected/i);

  const scanAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_SCAN_RESULT');
  assert.ok(scanAudit);
  assert.equal(scanAudit.details?.scanStatus, 'INFECTED');

  const failedAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_UPLOAD_FAILED');
  assert.ok(failedAudit);
  assert.equal(failedAudit.reasonCode, 'MALWARE_DETECTED');

  const quarantineKey = failedAudit.details?.quarantineKey;
  assert.ok(quarantineKey);
  const existsInQuarantine = await storage.objectExists(storage.quarantineBucket, quarantineKey);
  assert.equal(existsInQuarantine, true);

  for (const log of recordedAudits) {
    const serialized = JSON.stringify(log, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    assert.equal(serialized.includes(eicarString), false);
    assert.equal(serialized.includes('dek'), false);
  }
});

test('Audit log details do not log DEK, IV, or plaintext file contents', async () => {
  const { ingestion, recordedAudits } = createIngestionHarness();

  const secretPlaintext = 'TOP SECRET CLEARANCE LEVEL 4 INTELLIGENCE REPORT';
  const cleanPdf = createSamplePdfBuffer(secretPlaintext);
  const stream = Readable.from([cleanPdf]);

  const principal = {
    userId: 102n,
    sessionId: 'session-3',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  try {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'classified_brief.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  } catch {
    // DB transaction may fail without postgres connection in unit test, expected
  }

  assert.ok(recordedAudits.length >= 2);
  for (const log of recordedAudits) {
    const serialized = JSON.stringify(log, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    assert.equal(
      serialized.includes(secretPlaintext),
      false,
      'Plaintext secret must not appear in audit log',
    );
    assert.equal(serialized.includes('"dek"'), false, 'DEK must not appear in audit log');
  }
});

test('DocumentIngestionService: saves description, retention date, classification history, and sets current_version_id on document', async () => {
  let createdDocument = null;
  let updatedDocument = null;
  let createdVersion = null;
  let createdClassification = null;

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async ({ data }) => {
            createdDocument = data;
            return { id: data.id, ...data };
          },
          update: async ({ where, data }) => {
            updatedDocument = { where, data };
            return { id: where.id, ...data };
          },
        },
        documentVersion: {
          create: async ({ data }) => {
            createdVersion = data;
            return { id: 'ver-123', ...data };
          },
        },
        documentClassificationHistory: {
          create: async ({ data }) => {
            createdClassification = data;
            return { id: 1n, ...data };
          },
        },
      }),
  };

  const { ingestion } = createIngestionHarness({ mockDb });
  const cleanPdf = createSamplePdfBuffer('Metadata and Classification Test Content');
  const stream = Readable.from([cleanPdf]);
  const principal = {
    userId: 201n,
    sessionId: 'session-metadata-test',
    username: 'uploader_user',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  const output = await ingestion.ingestDocument({
    fileStream: stream,
    rawFilename: 'test_report.pdf',
    declaredMime: 'application/pdf',
    title: 'Financial Audit 2026',
    departmentId: 5n,
    documentCode: 'DOC-FIN-001',
    description: 'Internal financial audit report',
    classificationLevelId: 3n,
    businessCategoryId: 1n,
    retentionUntil: '2027-12-31',
    changeNote: 'Initial upload',
    principal,
    context,
  });

  assert.equal(output.scanStatus, 'CLEAN');
  assert.equal(output.status, 'DRAFT');
  assert.equal(output.versionNo, 1);

  assert.ok(createdDocument);
  assert.equal(createdDocument.title, 'Financial Audit 2026');
  assert.equal(createdDocument.document_code, 'DOC-FIN-001');
  assert.equal(createdDocument.description, 'Internal financial audit report');
  assert.equal(createdDocument.department_id, 5n);
  assert.equal(createdDocument.owner_id, 201n);
  assert.equal(createdDocument.retention_until?.toISOString(), '2027-12-31T00:00:00.000Z');

  assert.ok(createdVersion);
  assert.equal(createdVersion.scan_status, 'CLEAN');
  assert.equal(createdVersion.version_no, 1);

  assert.ok(updatedDocument);
  assert.equal(updatedDocument.data.current_version_id, 'ver-123');

  assert.ok(createdClassification);
  assert.equal(createdClassification.classification_level_id, 3n);
  assert.equal(createdClassification.business_category_id, 1n);
  assert.equal(createdClassification.classified_by, 201n);
});
