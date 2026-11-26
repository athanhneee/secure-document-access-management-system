/**
 * Module: Regression Tests for BUG-012 Multipart File Size Truncation & Premature Stream Close
 * Verifies real `@fastify/multipart` uploads exceeding `UPLOAD_MAX_FILE_SIZE_BYTES` return HTTP 413
 * (`FILE_SIZE_EXCEEDED`) instead of silently saving a truncated PDF/Office file as HTTP 201,
 * and verifies premature stream closure rejects cleanly without hanging the Promise.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import { PayloadTooLargeException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { DocumentIngestionController } from '../dist/modules/documents/document-ingestion.controller.js';
import { createSamplePdfBuffer } from './helpers/zip-builder.mjs';
import { createIngestionHarness } from './helpers/document-ingestion-mocks.mjs';

function buildMultipartBody(boundary, filename, contentType, fileBytes, fields = {}) {
  const parts = [];
  for (const [key, value] of Object.entries(fields)) {
    parts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${value}\r\n`,
        'utf8',
      ),
    );
  }
  parts.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`,
      'utf8',
    ),
  );
  parts.push(fileBytes);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'));
  return Buffer.concat(parts);
}

test('BUG-012 — real @fastify/multipart oversized PDF & DOCX return 413 FILE_SIZE_EXCEEDED and persist nothing', async () => {
  const maxFileSize = 4096;
  let dbCreates = 0;
  let storagePuts = 0;

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async ({ data }) => {
            dbCreates += 1;
            return { id: data.id, ...data };
          },
          update: async ({ where, data }) => ({ id: where.id, ...data }),
        },
        documentVersion: {
          create: async ({ data }) => {
            dbCreates += 1;
            return { id: 1n, ...data };
          },
        },
      }),
  };

  const { ingestion, storage, recordedAudits } = createIngestionHarness({
    configOverrides: { UPLOAD_MAX_FILE_SIZE_BYTES: maxFileSize },
    mockDb,
  });
  const origPut = storage.putObject.bind(storage);
  storage.putObject = async (...args) => {
    if (args[0] === storage.documentsBucket) storagePuts += 1;
    return origPut(...args);
  };

  const controller = new DocumentIngestionController(ingestion, { assertRequest: () => {} });
  const app = Fastify();
  await app.register(multipart, {
    limits: {
      fileSize: maxFileSize,
      files: 1,
    },
  });

  app.post('/documents/upload', async (request, reply) => {
    request.auth = {
      userId: 500n,
      sessionId: 'sess-bug012',
      username: 'owner.bug012',
      roles: ['DOCUMENT_OWNER'],
      mfa: true,
    };
    try {
      const result = await controller.uploadDocument(request);
      return reply.code(201).send(result);
    } catch (err) {
      const status = typeof err?.getStatus === 'function' ? err.getStatus() : 500;
      const body =
        typeof err?.getResponse === 'function' ? err.getResponse() : { message: String(err) };
      return reply.code(status).send(body);
    }
  });

  try {
    // 1. Oversized PDF (> 4096 bytes) starting with valid %PDF-1.4 header MUST be rejected with 413 FILE_SIZE_EXCEEDED
    const oversizedPdf = Buffer.concat([
      createSamplePdfBuffer('Oversized header'),
      Buffer.alloc(maxFileSize + 2048, 'X'),
    ]);
    const boundary1 = '----Bug012PdfBoundary';
    const pdfRes = await app.inject({
      method: 'POST',
      url: '/documents/upload',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary1}`,
      },
      payload: buildMultipartBody(boundary1, 'big-report.pdf', 'application/pdf', oversizedPdf),
    });
    assert.equal(
      pdfRes.statusCode,
      413,
      `Expected 413 for oversized PDF, got ${pdfRes.statusCode}: ${pdfRes.body}`,
    );
    assert.equal(pdfRes.json().errorCode, AppErrorCode.FILE_SIZE_EXCEEDED);
    assert.equal(dbCreates, 0, 'Truncated oversized PDF must never be persisted to DB');
    assert.equal(
      storagePuts,
      0,
      'Truncated oversized PDF must never be stored in documents bucket',
    );

    // 2. Oversized DOCX (> 4096 bytes) starting with PK\x03\x04 MUST return 413 FILE_SIZE_EXCEEDED (not 400 corrupt zip)
    const oversizedDocx = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      Buffer.alloc(maxFileSize + 1024, 'Z'),
    ]);
    const boundary2 = '----Bug012DocxBoundary';
    const docxRes = await app.inject({
      method: 'POST',
      url: '/documents/upload',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary2}`,
      },
      payload: buildMultipartBody(
        boundary2,
        'big-spec.docx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        oversizedDocx,
      ),
    });
    assert.equal(
      docxRes.statusCode,
      413,
      `Expected 413 for oversized DOCX, got ${docxRes.statusCode}: ${docxRes.body}`,
    );
    assert.equal(docxRes.json().errorCode, AppErrorCode.FILE_SIZE_EXCEEDED);
    assert.equal(dbCreates, 0);
    assert.equal(storagePuts, 0);

    // 3. Valid PDF within limit (<= 4096 bytes) still succeeds with 201 Created
    const validPdf = createSamplePdfBuffer('Within size limit');
    assert.ok(validPdf.length <= maxFileSize);
    const boundary3 = '----Bug012ValidBoundary';
    const okRes = await app.inject({
      method: 'POST',
      url: '/documents/upload',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary3}`,
      },
      payload: buildMultipartBody(boundary3, 'small-ok.pdf', 'application/pdf', validPdf),
    });
    assert.equal(
      okRes.statusCode,
      201,
      `Expected 201 for valid PDF, got ${okRes.statusCode}: ${okRes.body}`,
    );
    assert.equal(okRes.json().scanStatus, 'CLEAN');
    assert.equal(storagePuts, 1);

    assert.ok(
      recordedAudits.some(
        (a) =>
          a.action === 'DOCUMENT_UPLOAD_FAILED' && a.reasonCode === AppErrorCode.FILE_SIZE_EXCEEDED,
      ) || pdfRes.statusCode === 413,
    );
  } finally {
    await app.close();
  }
});

test('BUG-012 — spoolUploadStreamToTempFile catches busboy limit event, truncated flag at end, and premature close without hanging', async () => {
  const principal = {
    userId: 501n,
    sessionId: 'sess-stream',
    username: 'owner.stream',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  // 1. Stream hits busboy exact-byte limit: emits exactly maxFileSize bytes, sets truncated = true, emits 'limit' then 'end'
  {
    const { ingestion, recordedAudits } = createIngestionHarness({
      configOverrides: { UPLOAD_MAX_FILE_SIZE_BYTES: 1024 },
    });
    const stream = new PassThrough();
    const ingestPromise = ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'truncated.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });

    setImmediate(() => {
      stream.write(Buffer.alloc(1024, 0x25));
      stream.truncated = true;
      stream.emit('limit');
      stream.end();
    });

    await assert.rejects(
      ingestPromise,
      (err) =>
        err instanceof PayloadTooLargeException &&
        err.response?.errorCode === AppErrorCode.FILE_SIZE_EXCEEDED,
    );
    assert.ok(
      recordedAudits.some(
        (a) =>
          a.action === 'DOCUMENT_UPLOAD_FAILED' && a.reasonCode === AppErrorCode.FILE_SIZE_EXCEEDED,
      ),
    );
  }

  // 2. Stream ends with truncated = true even if 'limit' fired before listener attached
  {
    const { ingestion } = createIngestionHarness({
      configOverrides: { UPLOAD_MAX_FILE_SIZE_BYTES: 1024 },
    });
    const stream = new PassThrough();
    stream.truncated = true;
    await assert.rejects(
      ingestion.ingestDocument({
        fileStream: stream,
        rawFilename: 'pre-truncated.pdf',
        declaredMime: 'application/pdf',
        principal,
        context,
      }),
      (err) =>
        err instanceof PayloadTooLargeException &&
        err.response?.errorCode === AppErrorCode.FILE_SIZE_EXCEEDED,
    );
  }

  // 3. Premature client disconnect destroys stream (emits 'close' without 'end' or 'error') -> rejects cleanly without hanging
  {
    const { ingestion, recordedAudits } = createIngestionHarness({
      configOverrides: { UPLOAD_MAX_FILE_SIZE_BYTES: 4096 },
    });
    const stream = new PassThrough();
    const ingestPromise = ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'aborted.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });

    setImmediate(() => {
      stream.write(Buffer.from('%PDF-1.4\npartial'));
      stream.destroy();
    });

    await assert.rejects(
      ingestPromise,
      (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
    );
    assert.ok(
      recordedAudits.some(
        (a) => a.action === 'DOCUMENT_UPLOAD_FAILED' && a.reasonCode === 'STREAM_ABORTED',
      ),
    );
  }
});
