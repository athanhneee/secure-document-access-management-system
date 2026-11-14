/**
 * Module: Unit Tests for Vault KMS Key Rotation, DEK Zeroization, Streaming S3/ClamAV, Temp Janitor & Export Queue
 * Thuật toán: Kiểm thử hồi quy 4 nhóm khắc phục trọng yếu:
 *   1. `VaultTransitKmsService` trích xuất tên khóa đã xoay vòng từ `keyRef` và `DocumentEncryptionService` xóa trắng DEK (`fill(0)`) khi phát sinh ngoại lệ.
 *   2. `ObjectStorageService` truyền luồng không ghép mảnh, `AntivirusScannerService` khớp EICAR gối đầu 68B kèm TCP backpressure, `TempFileJanitorService` dọn rác quá 15 phút.
 *   3. `ExportJobService` giữ trạng thái `PENDING` kèm `__allowedDepartmentIds` cho worker, khử công thức Excel qua `sanitizeCsvCell`, thử lại giao dịch `P2034` và gom lô `createMany` hạn lưu trữ.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import crypto, { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import ExcelJS from 'exceljs';
import {
  VaultTransitKmsService,
  parseVaultKeyNameFromRef,
} from '../dist/modules/documents/kms/vault-transit-kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';
import {
  AntivirusScannerService,
  createChunkedEicarMatcher,
} from '../dist/modules/documents/antivirus-scanner.service.js';
import { TempFileJanitorService } from '../dist/modules/documents/temp-file-janitor.service.js';
import { runSerializableAuditTransaction } from '../dist/modules/documents/document-audit.service.js';
import { executeCheckRetentionWarnings } from '../dist/modules/documents/document-retention.helper.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';
import { generateExcelTable } from '../dist/modules/reports/export-formatter.js';
import { createMockConfig } from './helpers/document-ingestion-mocks.mjs';

test('[HIGH 1.4] VaultTransitKmsService parses rotated keyRef names & DocumentEncryptionService zeroes DEK on error', async () => {
  assert.equal(parseVaultKeyNameFromRef('vault-kms:rotated-kek:v2', 'default-kek'), 'rotated-kek');
  assert.equal(parseVaultKeyNameFromRef('vault:rotated-kek:v3', 'default-kek'), 'rotated-kek');
  assert.equal(parseVaultKeyNameFromRef('transit/archive-kek', 'default-kek'), 'archive-kek');
  assert.equal(parseVaultKeyNameFromRef('legacy-kek:v4', 'default-kek'), 'legacy-kek');
  assert.equal(parseVaultKeyNameFromRef('vault:v1', 'default-kek'), 'default-kek');

  const requestedUrls = [];
  const rawDek = crypto.randomBytes(32);
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    requestedUrls.push(String(url));
    return {
      ok: true,
      status: 200,
      json: async () => ({ data: { plaintext: rawDek.toString('base64') } }),
    };
  };
  try {
    const vaultKms = new VaultTransitKmsService(
      createMockConfig({ VAULT_TOKEN: 's.real-token', VAULT_KEY_NAME: 'current-kek' }),
    );
    const wrapped = Buffer.from('vault:v2:ciphertext', 'utf8').toString('base64url');
    const out = await vaultKms.unwrapKey(wrapped, 'vault:rotated-2025-kek:v2', 'doc-aad');
    assert.deepEqual(out, rawDek);
    assert.match(requestedUrls[0], /\/v1\/transit\/decrypt\/rotated-2025-kek$/);
  } finally {
    globalThis.fetch = origFetch;
  }

  let capturedEncryptDek = null;
  let capturedDecryptDek = null;
  const failingKms = {
    wrapKey: async (dek) => {
      capturedEncryptDek = dek;
      throw new Error('KMS outage');
    },
    unwrapCombinedRef: async () => {
      capturedDecryptDek = Buffer.alloc(32, 0xaa);
      return capturedDecryptDek;
    },
  };
  const enc = new DocumentEncryptionService(failingKms);
  await assert.rejects(() => enc.encryptBuffer(Buffer.from('secret')), /KMS outage/);
  assert.ok(
    capturedEncryptDek.every((b) => b === 0),
    'DEK must be zeroed when wrapKey throws',
  );

  const badHeaderValid = Buffer.concat([
    Buffer.from('SDAE'),
    Buffer.from([0x01]),
    Buffer.alloc(28, 1),
    Buffer.from('bad'),
  ]);
  await assert.rejects(() => enc.decryptToTempFile(badHeaderValid, 'local-kms:v1:abc'));
  assert.ok(
    capturedDecryptDek.every((b) => b === 0),
    'DEK must be zeroed when GCM auth fails',
  );
});

test('[CRITICAL 1.5.1] Streaming ObjectStorage, 68B-overlap EICAR ClamAV backpressure & TempFileJanitor', async () => {
  const config = createMockConfig();
  const storage = new ObjectStorageService(config);
  await storage.putObject(
    storage.documentsBucket,
    'k1',
    Readable.from([Buffer.from('hel'), Buffer.from('lo')]),
  );
  const meta = await storage.headObject(storage.documentsBucket, 'k1');
  assert.equal(meta?.contentLength, 5);
  const chunks = [];
  for await (const c of await storage.getObjectStream(storage.documentsBucket, 'k1')) {
    chunks.push(Buffer.from(c));
  }
  assert.equal(Buffer.concat(chunks).toString('utf8'), 'hello');

  const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const matcher = createChunkedEicarMatcher();
  assert.equal(matcher.inspectChunk(Buffer.from(eicar.slice(0, 31), 'ascii')), false);
  assert.equal(matcher.inspectChunk(Buffer.from(eicar.slice(31), 'ascii')), true);

  const server = net.createServer((sock) => {
    let total = Buffer.alloc(0);
    sock.on('data', (d) => {
      total = Buffer.concat([total, d]);
      if (total.length >= 14 && total.subarray(-4).equals(Buffer.alloc(4, 0))) {
        sock.end('stream: OK\0');
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const port = server.address().port;
    const scanner = new AntivirusScannerService(
      createMockConfig({ CLAMAV_HOST: '127.0.0.1', CLAMAV_PORT: port }),
    );
    const cleanRes = await scanner.scan(
      Readable.from([Buffer.alloc(40_000, 0x41), Buffer.alloc(40_000, 0x42)]),
    );
    assert.equal(cleanRes.status, 'CLEAN');
    const splitRes = await scanner.scan(
      Readable.from([Buffer.from(eicar.slice(0, 20)), Buffer.from(eicar.slice(20))]),
    );
    assert.equal(splitRes.status, 'INFECTED');
  } finally {
    server.close();
  }

  const sandboxTmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'janitor-sandbox-'));
  try {
    const staleDir = path.join(sandboxTmp, 'sda-dec-stale');
    const freshDir = path.join(sandboxTmp, 'sda-ing-fresh');
    await fsp.mkdir(staleDir);
    await fsp.mkdir(freshDir);
    const oldTime = new Date(Date.now() - 20 * 60_000);
    await fsp.utimes(staleDir, oldTime, oldTime);
    const janitor = new TempFileJanitorService();
    const swept = await janitor.sweepStaleTempEntries(15 * 60_000, sandboxTmp);
    assert.equal(swept, 1);
    const remaining = await fsp.readdir(sandboxTmp);
    assert.deepEqual(remaining, ['sda-ing-fresh']);
  } finally {
    await fsp.rm(sandboxTmp, { recursive: true, force: true });
  }
});

test('[HIGH 1.3 & 2.1] Export worker queue contract, Excel formula sanitization, P2034 retry & batched retention', async () => {
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

  const prevMode = process.env['EXPORT_EXECUTION_MODE'];
  const tmpExportDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-exp-test-'));
  process.env['EXPORT_STORAGE_DIR'] = tmpExportDir;
  process.env['EXPORT_EXECUTION_MODE'] = 'worker';
  try {
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
    const exportSvc = new ExportJobService(mockDb, { writeLog: async () => {} }, mockAuthz);
    const created = await exportSvc.createExportJob(
      { exportType: 'AUDIT_LOGS', format: 'EXCEL', filterParams: {} },
      actor,
      randomUUID(),
    );
    assert.equal(created.status, 'PENDING');
    assert.deepEqual(jobs[created.id].filter_params.__allowedDepartmentIds, ['10', '20']);

    await exportSvc.processPendingJobById(created.id);
    assert.equal(jobs[created.id].status, 'COMPLETED');
    const downloaded = await exportSvc.downloadExportJob(created.id, actor);
    assert.ok(downloaded.buffer.length > 0);

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
    if (prevMode === undefined) delete process.env['EXPORT_EXECUTION_MODE'];
    else process.env['EXPORT_EXECUTION_MODE'] = prevMode;
    delete process.env['EXPORT_STORAGE_DIR'];
    await fsp.rm(tmpExportDir, { recursive: true, force: true });
  }

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
});
