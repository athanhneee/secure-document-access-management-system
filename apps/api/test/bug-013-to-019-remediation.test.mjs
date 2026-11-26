import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { VerifyAuditChainSchema } from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { validateEnv } from '../dist/config/env.schema.js';
import { createPartitionAnchor } from '../dist/modules/audit/audit-anchor.helper.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { activeRedisRetryStrategy } from '../dist/modules/concurrency/distributed-state-pubsub.helper.js';
import { renderExportBuffer } from '../dist/modules/reports/export-artifact.helper.js';
import { buildExportDataset } from '../dist/modules/reports/export-dataset.builder.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';
import {
  buildAuditLogExportWhere,
  buildIncidentReportExportWhere,
} from '../dist/modules/reports/export-where-builders.helper.js';
import { normalizeExportFilters } from '../dist/modules/reports/export-filter-scope.helper.js';
import { createAuditWriterHarness } from './helpers/audit-trail-mocks.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

test('[BUG-013] createPartitionAnchor refuses VALID anchor on tampered chain; fullScan detects history tampering behind anchor K without inflating totalChecked', async () => {
  const { config, writer, logs, mockTx } = createAuditWriterHarness();
  const ctx = { ip: '127.0.0.1', correlationId: randomUUID() };
  for (let i = 1; i <= 5; i++) {
    await writer.record(
      { action: `ACTION_${i}`, outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'AUDIT_B13' },
      ctx,
      mockTx,
    );
  }

  // Tamper row #2 content while keeping its entry_hash intact
  const tamperedLogs = logs.map((row) =>
    row.chain_sequence === 2n ? { ...row, action: 'TAMPERED_DB_ACTION' } : row,
  );
  const key = config.get('AUDIT_INTEGRITY_KEY');
  const anchor5Sig = createHmac('sha256', key)
    .update(`AUDIT_B13:5:${logs[4].entry_hash}`)
    .digest('hex');

  const securityPrincipal = {
    userId: 9n,
    sessionId: randomUUID(),
    username: 'sec.demo',
    roles: ['SECURITY_OFFICER'],
    mfa: true,
  };

  let anchorInsertAttempted = false;
  const tamperedDb = {
    auditLog: {
      count: async () => tamperedLogs.length,
      findFirst: async ({ where, orderBy }) => {
        if (orderBy?.chain_sequence === 'desc') return tamperedLogs[tamperedLogs.length - 1];
        return tamperedLogs.find((l) => l.chain_sequence === where?.chain_sequence) ?? null;
      },
      findMany: async ({ where }) =>
        tamperedLogs.filter((l) =>
          where?.chain_sequence?.gt ? l.chain_sequence > where.chain_sequence.gt : true,
        ),
    },
    auditAnchor: {
      findMany: async () => [],
      create: async ({ data }) => {
        anchorInsertAttempted = true;
        return { id: 1n, anchored_at: new Date(), ...data };
      },
    },
    $transaction: async (fn) =>
      fn({
        securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
        alertAuditLink: { create: async () => ({}) },
      }),
  };

  // 1. createPartitionAnchor MUST refuse to stamp status='VALID' when row #2 is tampered
  await assert.rejects(
    () => createPartitionAnchor(tamperedDb, writer, securityPrincipal, 'AUDIT_B13'),
    (err) => err instanceof ConflictException,
  );
  assert.equal(anchorInsertAttempted, false, 'Must not persist VALID anchor on tampered chain');

  // 2. When chain is intact, createPartitionAnchor succeeds after full verification
  const cleanAnchors = [];
  const cleanDb = {
    auditLog: {
      count: async () => logs.length,
      findFirst: async ({ where, orderBy }) => {
        if (orderBy?.chain_sequence === 'desc') return logs[logs.length - 1];
        return logs.find((l) => l.chain_sequence === where?.chain_sequence) ?? null;
      },
      findMany: async ({ where }) =>
        logs.filter((l) =>
          where?.chain_sequence?.gt ? l.chain_sequence > where.chain_sequence.gt : true,
        ),
    },
    auditAnchor: {
      findMany: async () => cleanAnchors,
      create: async ({ data }) => {
        const created = { id: 10n, anchored_at: new Date(), ...data };
        cleanAnchors.push(created);
        return created;
      },
    },
  };
  const createdAnchor = await createPartitionAnchor(
    cleanDb,
    writer,
    securityPrincipal,
    'AUDIT_B13',
  );
  assert.equal(createdAnchor.status, 'VALID');
  assert.equal(createdAnchor.anchorSequence, '5');

  // 3. With anchor at 5, incremental mode must NOT inflate totalChecked to 5; fullScan: true MUST detect row #2 tampering
  const verifierDb = {
    ...tamperedDb,
    auditAnchor: {
      findMany: async () => [
        {
          chain_partition: 'AUDIT_B13',
          anchor_sequence: 5n,
          entry_hash: logs[4].entry_hash,
          signature: anchor5Sig,
          signer_key_id: 'v1',
          status: 'VALID',
        },
      ],
    },
  };
  const verifier = new AuditVerifierService(writer, verifierDb);
  const incremental = await verifier.verifyPartition('AUDIT_B13');
  assert.equal(incremental.totalChecked, 1, 'Must only count the 1 verified anchor row, not 5');
  assert.equal(incremental.skippedBeforeAnchor, 4);
  assert.equal(incremental.verificationMode, 'INCREMENTAL');

  const fullScan = await verifier.verifyPartition('AUDIT_B13', { fullScan: true });
  assert.equal(fullScan.valid, false);
  assert.equal(fullScan.totalChecked, 5);
  assert.equal(fullScan.skippedBeforeAnchor, 0);
  assert.equal(fullScan.verificationMode, 'FULL');
  assert.ok(
    fullScan.violations.some((v) => v.code === 'AUDIT_LOG_TAMPERED' && v.sequence === 2n),
    'fullScan must detect DB tampering on historical row #2 behind anchor #5',
  );

  assert.equal(VerifyAuditChainSchema.parse({ fullScan: 'true' }).fullScan, true);
  assert.equal(VerifyAuditChainSchema.parse({ fullScan: 'false' }).fullScan, false);
});

test('[BUG-014] ExportJobService persists normalized filters, supports correlationId UUID equals, IN_REVIEW incidents, and unified JSON envelope', async () => {
  const corrUuid = randomUUID();
  const docUuid = randomUUID();
  const persistedJobs = new Map();

  const mockDb = {
    asyncExportJob: {
      create: async ({ data }) => {
        const row = { ...data, created_at: new Date(), completed_at: null, row_count: 0 };
        persistedJobs.set(data.id, row);
        return row;
      },
      update: async ({ where, data }) => Object.assign(persistedJobs.get(where.id), data),
      findUnique: async ({ where }) => persistedJobs.get(where.id) ?? null,
    },
    securityAlert: { findMany: async () => [] },
    incidentReport: { findMany: async () => [] },
    auditLog: { findMany: async () => [] },
  };
  const mockAuthz = {
    hasPermission: async () => true,
    visibleDepartmentIds: async () => [10n, 20n],
  };
  const actor = {
    userId: 5n,
    username: 'sec.demo',
    sessionId: randomUUID(),
    roles: ['SECURITY_OFFICER'],
    mfa: true,
  };

  const prevMode = process.env['EXPORT_EXECUTION_MODE'];
  process.env['EXPORT_EXECUTION_MODE'] = 'worker';
  try {
    const svc = new ExportJobService(mockDb, undefined, mockAuthz);

    // Lowercase enum "open" + excessive limit 99999 + departmentId "10" must be normalized BEFORE persisting
    const job = await svc.createExportJob(
      {
        exportType: 'SECURITY_ALERTS',
        format: 'JSON',
        filterParams: { status: 'open', severity: 'high', limit: 99999, departmentId: '10' },
      },
      actor,
    );
    const saved = persistedJobs.get(job.id);
    assert.equal(saved.filter_params.status, 'OPEN');
    assert.equal(saved.filter_params.severity, 'HIGH');
    assert.equal(saved.filter_params.limit, 1000);
    assert.equal(saved.filter_params.departmentId, '10');
    assert.deepEqual(saved.filter_params.__allowedDepartmentIds, ['10']);

    // Invalid UUID correlationId must be rejected upfront with 400
    await assert.rejects(
      () =>
        svc.createExportJob(
          {
            exportType: 'AUDIT_LOGS',
            format: 'JSON',
            filterParams: { correlationId: 'not-a-valid-uuid' },
          },
          actor,
        ),
      (err) => err instanceof BadRequestException,
    );
  } finally {
    if (prevMode === undefined) delete process.env['EXPORT_EXECUTION_MODE'];
    else process.env['EXPORT_EXECUTION_MODE'] = prevMode;
  }

  // Exact UUID equals for audit correlation_id (never ILIKE contains)
  const auditFilters = normalizeExportFilters(
    { correlationId: corrUuid, outcome: 'success' },
    null,
    'AUDIT_LOGS',
  );
  const auditWhere = buildAuditLogExportWhere(auditFilters);
  assert.deepEqual(auditWhere.correlation_id, { equals: corrUuid });
  assert.equal(auditWhere.outcome, 'SUCCESS');

  // INCIDENT_REPORTS supports IN_REVIEW, incidentCode, documentId, ruleCode & department scope on alerts
  const incidentFilters = normalizeExportFilters(
    {
      status: 'in_review',
      incidentCode: 'INC-2026-009',
      documentId: docUuid,
      ruleCode: 'MASS_DOWNLOAD',
    },
    [10n],
    'INCIDENT_REPORTS',
  );
  const incidentWhere = buildIncidentReportExportWhere(incidentFilters);
  assert.equal(incidentWhere.status, 'IN_REVIEW');
  assert.equal(incidentWhere.incident_code, 'INC-2026-009');
  assert.deepEqual(incidentWhere.security_alerts, {
    document_id: docUuid,
    alert_type: 'MASS_DOWNLOAD',
  });
  assert.ok(Array.isArray(incidentWhere.OR));
  assert.equal(incidentWhere.OR.length, 2);

  // Unified JSON export envelope matches Worker ({ exportType, generatedAt, rowCount, items })
  const dataset = await buildExportDataset(
    {
      systemHealthSnapshot: {
        findMany: async () => [
          {
            id: 7n,
            service_name: 'api',
            status: 'HEALTHY',
            response_time_ms: 12,
            error_count: 0,
            captured_at: new Date('2026-11-26T00:00:00.000Z'),
          },
        ],
      },
    },
    'SYSTEM_REPORT',
    {},
    null,
  );
  const rendered = await renderExportBuffer('JSON', dataset, new Date('2026-11-26T00:01:00.000Z'));
  const parsed = JSON.parse(rendered.contentBuffer.toString('utf8'));
  assert.equal(parsed.exportType, 'SYSTEM_REPORT');
  assert.equal(parsed.generatedAt, '2026-11-26T00:01:00.000Z');
  assert.equal(parsed.rowCount, 1);
  assert.equal(Array.isArray(parsed.items), true);
  assert.equal(parsed.items[0].service_name, 'api');
});

test('[BUG-015] activeRedisRetryStrategy never returns null and caps backoff at 5000ms', () => {
  assert.equal(activeRedisRetryStrategy(1), 250);
  assert.equal(activeRedisRetryStrategy(5), 1_250);
  assert.equal(activeRedisRetryStrategy(6), 1_500);
  assert.equal(activeRedisRetryStrategy(20), 5_000);
  assert.equal(activeRedisRetryStrategy(100), 5_000);
  for (const attempt of [1, 5, 6, 10, 50, 1_000]) {
    const delay = activeRedisRetryStrategy(attempt);
    assert.equal(typeof delay, 'number');
    assert.ok(delay > 0 && delay <= 5_000);
  }
});

test('[BUG-019] compose.prod.yaml forwards ABAC_TRUSTED_NETWORK_CIDRS & AUTH_ACTIVE_KID, and env.schema normalizes empty optional strings to undefined', () => {
  const composeProd = fs.readFileSync(path.join(repoRoot, 'infra/compose.prod.yaml'), 'utf8');
  assert.match(composeProd, /ABAC_TRUSTED_NETWORK_CIDRS:\s*\$\{ABAC_TRUSTED_NETWORK_CIDRS:\?/);
  assert.match(composeProd, /AUTH_ACTIVE_KID:\s*\$\{AUTH_ACTIVE_KID:\?/);

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const prodComposeEnv = {
    NODE_ENV: 'production',
    PORT: '3001',
    HOST: '0.0.0.0',
    TRUST_PROXY: 'loopback,uniquelocal',
    ABAC_TRUSTED_NETWORK_CIDRS: '10.20.0.0/16',
    CORS_ALLOWED_ORIGINS: 'https://docs.example.com',
    DATABASE_URL: 'postgresql://sda_app:fixture-password@postgres:5432/sda',
    REDIS_URL: 'redis://:fixture-password@redis:6379/0',
    APP_ENCRYPTION_MASTER_KEY: 'prod-master-key-with-sufficient-entropy-32-chars!!',
    AUDIT_INTEGRITY_KEY: 'prod-audit-integrity-key-sufficient-entropy-32b!!',
    DOCUMENT_AUDIT_HMAC_KEY: 'prod-doc-audit-hmac-key-sufficient-entropy-32b!!',
    AUTH_AUDIT_HMAC_KEY: 'prod-auth-audit-hmac-key-sufficient-entropy-32b!!',
    AUDIT_KEY_ROTATION_JSON: '',
    AUTH_ACTIVE_KID: 'prod-ed25519-2026-q4',
    AUTH_SIGNING_PRIVATE_KEY_PEM: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([
      {
        kid: 'prod-ed25519-2026-q4',
        publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    ]),
    STORAGE_ACCESS_KEY: 'prod-s3-access-key',
    STORAGE_SECRET_KEY: 'prod-s3-secret-key-value',
    WEBAUTHN_RP_ID: 'docs.example.com',
    WEBAUTHN_ORIGINS: 'https://docs.example.com',
    PASSWORD_RESET_BASE_URL: 'https://docs.example.com/reset-password',
    SMTP_HOST: '',
    SMTP_USER: '',
    SMTP_PASS: '',
    METRICS_SCRAPE_TOKEN: '',
    DATABASE_CA_CERT: '',
    EXPORT_STORAGE_DIR: '/var/lib/sda/exports',
  };

  const validated = validateEnv(prodComposeEnv);
  assert.equal(validated.SMTP_USER, undefined);
  assert.equal(validated.SMTP_PASS, undefined);
  assert.equal(validated.METRICS_SCRAPE_TOKEN, undefined);
  assert.equal(validated.AUDIT_KEY_ROTATION_JSON, undefined);
  assert.equal(validated.DATABASE_CA_CERT, undefined);
  assert.equal(validated.AUTH_ACTIVE_KID, 'prod-ed25519-2026-q4');

  // Non-empty invalid METRICS_SCRAPE_TOKEN must STILL fail min(16)
  assert.throws(
    () => validateEnv({ ...prodComposeEnv, METRICS_SCRAPE_TOKEN: 'too-short' }),
    /METRICS_SCRAPE_TOKEN/,
  );

  // TokenService must boot cleanly with the validated production config
  const tokenService = new TokenService(new AppConfigService(validated));
  assert.ok(tokenService);
});
