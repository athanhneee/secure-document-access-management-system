import assert from 'node:assert/strict';
import http from 'node:http';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import ExcelJS from 'exceljs';
import { ForbiddenException } from '@nestjs/common';
import { runSerializableAuditTransaction } from '../../dist/modules/documents/document-audit.service.js';
import { executeCheckRetentionWarnings } from '../../dist/modules/documents/document-retention.helper.js';
import { ExportJobService } from '../../dist/modules/reports/export-job.service.js';
import { generateExcelTable } from '../../dist/modules/reports/export-formatter.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ kịch bản trợ giúp kiểm thử hàng đợi xuất báo cáo `@sda/api`, tải chéo đa container qua Cloudflare R2 / S3,
 * khử công thức `ExcelJS`, thử lại giao dịch `P2034` và gom lô cảnh báo hạn lưu trữ.
 */

export async function startInMemoryS3Server() {
  const objects = new Map();
  const requests = [];
  const server = http.createServer((req, res) => {
    const urlPath = (req.url ?? '/').split('?')[0];
    requests.push({ method: req.method, path: urlPath });
    if (req.method === 'PUT') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        objects.set(urlPath, Buffer.concat(chunks));
        res.writeHead(200, { ETag: '"mock-etag"' });
        res.end();
      });
      return;
    }
    if (req.method === 'GET') {
      const payload = objects.get(urlPath);
      if (!payload) {
        res.writeHead(404, { 'Content-Type': 'application/xml' });
        res.end('<Error><Code>NoSuchKey</Code></Error>');
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payload.byteLength),
      });
      res.end(payload);
      return;
    }
    res.writeHead(204);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    objects,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export async function assertExportQueueAndMultiContainerR2() {
  const jobs = Object.create(null);
  const mockDb = {
    asyncExportJob: {
      create: async ({ data }) => {
        jobs[data.id] = {
          ...data,
          file_path: null,
          file_size_bytes: null,
          sha256_hash: null,
          mime_type: null,
          row_count: 0,
          error_message: null,
          created_at: new Date(),
          completed_at: null,
        };
        return jobs[data.id];
      },
      findUnique: async ({ where }) => jobs[where.id] ?? null,
      update: async ({ where, data }) => {
        Object.assign(jobs[where.id], data);
        return jobs[where.id];
      },
    },
    auditLog: {
      findMany: async () => [
        {
          id: 1n,
          occurred_at: new Date(),
          actor_username: '  =1+1',
          action: 'LOGIN',
          object_type: 'USER',
          object_id: '1',
          outcome: 'SUCCESS',
          ip_address: '127.0.0.1',
          chain_partition: 'AUDIT',
          chain_sequence: 1n,
          entry_hash: 'h1',
        },
      ],
    },
  };

  const s3Server = await startInMemoryS3Server();
  const dirContainerA = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-exp-a-'));
  const dirContainerB = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-exp-b-'));
  const savedEnv = {
    NODE_ENV: process.env['NODE_ENV'],
    STORAGE_MOCK: process.env['STORAGE_MOCK'],
    STORAGE_ENDPOINT: process.env['STORAGE_ENDPOINT'],
    STORAGE_ACCESS_KEY: process.env['STORAGE_ACCESS_KEY'],
    STORAGE_SECRET_KEY: process.env['STORAGE_SECRET_KEY'],
    STORAGE_BUCKET_DERIVATIVES: process.env['STORAGE_BUCKET_DERIVATIVES'],
    EXPORT_ENCRYPTION_KEY: process.env['EXPORT_ENCRYPTION_KEY'],
    EXPORT_EXECUTION_MODE: process.env['EXPORT_EXECUTION_MODE'],
    EXPORT_STORAGE_DIR: process.env['EXPORT_STORAGE_DIR'],
  };

  try {
    process.env['NODE_ENV'] = 'production';
    process.env['STORAGE_MOCK'] = 'false';
    process.env['STORAGE_ENDPOINT'] = s3Server.endpoint;
    process.env['STORAGE_ACCESS_KEY'] = 'r2-access-key-example';
    process.env['STORAGE_SECRET_KEY'] = 'r2-secret-key-example';
    process.env['STORAGE_BUCKET_DERIVATIVES'] = 'sda-derivatives';
    process.env['EXPORT_ENCRYPTION_KEY'] = 'shared-multi-container-export-key-32b!!';
    process.env['EXPORT_EXECUTION_MODE'] = 'worker';
    process.env['EXPORT_STORAGE_DIR'] = dirContainerA;

    const mockAuthz = {
      hasPermission: async () => true,
      visibleDepartmentIds: async () => [10n, 20n],
    };
    const actor = {
      userId: 9n,
      sessionId: 's-9',
      username: 'auditor',
      roles: ['AUDITOR'],
      mfa: true,
    };
    const svcContainerA = new ExportJobService(mockDb, { writeLog: async () => {} }, mockAuthz);
    const created = await svcContainerA.createExportJob(
      { exportType: 'AUDIT_LOGS', format: 'EXCEL', filterParams: {} },
      actor,
      randomUUID(),
    );
    assert.equal(created.status, 'PENDING');
    assert.deepEqual(jobs[created.id].filter_params.__allowedDepartmentIds, ['10', '20']);

    await svcContainerA.processPendingJobById(created.id);
    assert.equal(jobs[created.id].status, 'COMPLETED');
    assert.ok(s3Server.objects.has(`/sda-derivatives/exports/${created.id}.dat`));

    // Simulate Container B without Container A's local filesystem
    process.env['EXPORT_STORAGE_DIR'] = dirContainerB;
    const svcContainerB = new ExportJobService(mockDb, { writeLog: async () => {} }, mockAuthz);
    const downloaded = await svcContainerB.downloadExportJob(created.id, actor);
    assert.equal(downloaded.filename.endsWith('.xlsx'), true);
    const loadedWb = new ExcelJS.Workbook();
    await loadedWb.xlsx.load(downloaded.buffer);
    assert.equal(loadedWb.worksheets.length, 1);

    // Tampered traversal path must still fail closed with ForbiddenException
    jobs[created.id].file_path = '/etc/passwd';
    await assert.rejects(
      () => svcContainerB.downloadExportJob(created.id, actor),
      (err) => err instanceof ForbiddenException,
    );

    const excelBuf = await generateExcelTable(
      'Test',
      [{ key: 'FormulaCol', header: 'FormulaCol' }],
      [{ FormulaCol: '  =1+1' }, { FormulaCol: '|cmd' }],
    );
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(excelBuf);
    const ws = wb.worksheets[0];
    assert.equal(ws.getRow(2).getCell(1).value, "'  =1+1");
    assert.equal(ws.getRow(3).getCell(1).value, "'|cmd");
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await s3Server.close();
    await fsp.rm(dirContainerA, { recursive: true, force: true });
    await fsp.rm(dirContainerB, { recursive: true, force: true });
  }
}

export async function assertSerializableRetryAndBatchedRetention() {
  let txAttempts = 0;
  await runSerializableAuditTransaction(
    {
      $transaction: async (fn) => {
        txAttempts += 1;
        if (txAttempts < 3) {
          const err = new Error('could not serialize access');
          err.code = 'P2034';
          throw err;
        }
        await fn({});
      },
    },
    async () => {},
  );
  assert.equal(txAttempts, 3);

  let permCalls = 0;
  let createManyCount = 0;
  const expiredAt = new Date(Date.now() - 86_400_000);
  await executeCheckRetentionWarnings({
    database: {
      document: {
        findMany: async () => [
          {
            id: randomUUID(),
            document_code: 'D1',
            title: 'T1',
            owner_id: 2n,
            department_id: 50n,
            retention_until: expiredAt,
          },
          {
            id: randomUUID(),
            document_code: 'D2',
            title: 'T2',
            owner_id: 3n,
            department_id: 50n,
            retention_until: expiredAt,
          },
        ],
      },
      notification: { createMany: async ({ data }) => (createManyCount += data.length) },
      securityAlert: { createMany: async () => {} },
    },
    authorization: { hasPermission: async () => ((permCalls += 1), true) },
    audit: { record: async () => {} },
    daysThreshold: 30,
    principal: {
      userId: 99n,
      sessionId: 's-99',
      username: 'mgr',
      roles: ['DOCUMENT_OWNER'],
      mfa: true,
    },
  });
  assert.equal(permCalls, 1, 'Duplicate department RBAC checks must be deduplicated');
  assert.equal(createManyCount, 2, 'Notifications must be batch-inserted via createMany');
}
