/**
 * Module: Bộ Kiểm Thử Hồi Quy Toàn Diện Khắc Phục `BUG-051` .. `BUG-069` (`@sda/api`)
 * Thuật toán: Xác minh độc lập từng bất biến bảo mật, chống đua tranh bộ nhớ đệm, chống lách SoD,
 *   toàn vẹn watermark, chuẩn hóa IPv6 RFC 5952 khớp `inet_out` PostgreSQL (PGlite), SSE đa phòng ban,
 *   Redlock quorum fallback, khóa HMAC/Export đồng bộ và khử trùng SOC/Notification.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { PGlite } from '@electric-sql/pglite';
import { AppErrorCode, resolvePrimaryAuditHmacKeyFromEnv } from '@sda/contracts';

process.env.DATABASE_URL ??= 'postgresql://postgres:fixture-password@127.0.0.1:5432/sda_unit_test';

import { AbacService } from '../dist/modules/abac/abac.service.js';
import { ABAC_POLICY_EPOCH_NAMESPACE, PolicyCache } from '../dist/modules/abac/policy-cache.js';
import { resolvePrimaryAuditHmacKey } from '../dist/modules/audit/audit-chain-helper.js';
import {
  AuditRedactionService,
  canonicalizePostgresInetAddress,
} from '../dist/modules/audit/audit-redaction.service.js';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { probeQuorumRedisHealthy } from '../dist/modules/concurrency/redlock-node.helper.js';
import { executeWatermarkedPreview } from '../dist/modules/documents/delivery-preview.helper.js';
import { reverifyRedeemedTicketState } from '../dist/modules/documents/delivery-ticket-redemption.helper.js';
import { loadValidatedDeliverySession } from '../dist/modules/documents/delivery-ticket.helper.js';
import {
  storeCachedSessionPdf,
  tryLoadCachedSessionPdf,
} from '../dist/modules/documents/derivative-pdf-cache.helper.js';
import { executeTransferDocumentOwner } from '../dist/modules/documents/document-ownership.helper.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { executeCheckRetentionWarnings } from '../dist/modules/documents/document-retention.helper.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import { renderSanitizedTextToPdf } from '../dist/modules/documents/office-fallback-pdf.js';
import { extractOfficeFallbackText } from '../dist/modules/documents/office-ooxml-extractor.helper.js';
import { ensurePermittedOwnerSystemGrant } from '../dist/modules/documents/pep-clearance.helper.js';
import { resolveAndEnforceSessionPolicy } from '../dist/modules/documents/session-policy-resolver.helper.js';
import { NotificationsController } from '../dist/modules/notifications/notifications.controller.js';
import { NotificationsService } from '../dist/modules/notifications/notifications.service.js';
import { ALLOW_AUTHENTICATED_SELF_METADATA } from '../dist/modules/rbac/require-permission.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import {
  decryptAndVerifyExportArtifactBuffer,
  encryptExportArtifactBuffer,
  resolveExportAtRestKey,
} from '../dist/modules/reports/export-disk-cipher.helper.js';
import { executeAddIncidentAction } from '../dist/modules/security-operations/incident-actions.helper.js';
import { executeSubmitIncidentReport } from '../dist/modules/security-operations/incident-transitions.helper.js';
import { IncidentsService } from '../dist/modules/security-operations/incidents.service.js';
import { resolveSocDateRangeBounds } from '../dist/modules/security-operations/security-alerts.helper.js';
import { SecurityAlertsService } from '../dist/modules/security-operations/security-alerts.service.js';
import { SecurityDetectionService } from '../dist/modules/security-operations/security-detection.service.js';
import { formatForensicWatermarkText } from '../dist/modules/watermarks/watermark-crypto.helper.js';
import {
  assertWatermarkTemplateHasRecipientIdentity,
  WatermarksService,
} from '../dist/modules/watermarks/watermarks.service.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

function makeMinimalConfig(map = {}) {
  return {
    get: (key) => map[key],
  };
}

function makeMockRedis(sharedStore = new Map()) {
  return {
    store: sharedStore,
    async get(k) {
      return sharedStore.has(k) ? sharedStore.get(k) : null;
    },
    async set(k, v) {
      sharedStore.set(k, String(v));
      return 'OK';
    },
    async del(...keys) {
      let n = 0;
      for (const k of keys) {
        if (sharedStore.delete(k)) n += 1;
      }
      return n;
    },
    async incr(k) {
      const next = (Number(sharedStore.get(k)) || 0) + 1;
      sharedStore.set(k, String(next));
      return next;
    },
    async pexpire() {
      return 1;
    },
    disconnect() {},
  };
}

async function createMinimalPdfBuffer() {
  const doc = await PDFDocument.create();
  doc.addPage([400, 400]);
  return Buffer.from(await doc.save());
}

test('BUG-051 — PolicyCache listens to DistributedStateService invalidations, keys compiled policy by (abacCacheEpoch, version), and avoids stale cache poisoning on post-commit epoch bump', async () => {
  const sharedRedisStore = new Map();
  const stateStore = new DistributedStateService();
  const redisPodA = makeMockRedis(sharedRedisStore);
  const redisPodB = makeMockRedis(sharedRedisStore);

  const cachePodA = new PolicyCache(undefined, redisPodA, stateStore);
  const cachePodB = new PolicyCache(undefined, redisPodB, stateStore);

  let committedRuleEffect = 'PERMIT';
  let sequenceVersion = 5n;
  const repo = {
    async currentPolicyVersion() {
      return sequenceVersion;
    },
    async loadConsistentPolicySnapshot() {
      return {
        version: sequenceVersion,
        definitions: [],
        rules: [
          {
            id: 1n,
            code: 'RULE-RACE',
            effect: committedRuleEffect,
            priority: 10,
            targetResource: 'DOCUMENT',
            targetAction: 'VIEW',
            combiningAlgorithm: 'DENY_OVERRIDES',
            validFrom: new Date('2026-01-01T00:00:00.000Z'),
            validTo: null,
            obligations: [],
            conditions: [
              {
                id: 1n,
                group: 1,
                sequence: 1,
                contextKey: 'subject.clearanceRank',
                operator: 'GTE',
                expectedValue: 1,
              },
            ],
          },
        ],
      };
    },
  };

  const abacPodA = new AbacService(repo, cachePodA, { record: async () => {} });
  const abacPodB = new AbacService(repo, cachePodB, { record: async () => {} });

  const evalInput = {
    resourceType: 'DOCUMENT',
    action: 'VIEW',
    subject: { clearanceRank: 2, departmentId: '1', employmentStatus: 'ACTIVE', projects: [] },
    resource: {
      classificationRank: 1,
      ownerId: '1',
      departmentId: '1',
      category: 'GEN',
      status: 'ACTIVE',
    },
    environment: {
      currentTime: '2026-06-15T04:00:00.000Z',
      ip: '10.0.0.1',
      trustedNetwork: true,
      deviceTrust: true,
      mfa: true,
      riskScore: 0,
    },
  };

  // Simulate sequence advancing to 6 BEFORE commit while rule still reads PERMIT
  sequenceVersion = 6n;
  const r1 = await abacPodA.evaluate(evalInput);
  assert.equal(r1.decision, 'PERMIT');
  assert.equal(r1.policyVersion, '6');

  // Verify Redis compiled key is epoch-prefixed (sda:abac:compiled:0:6)
  assert.ok(sharedRedisStore.has('sda:abac:compiled:0:6'));

  // Now policy mutation commits DENY and bumps epoch AFTER commit
  committedRuleEffect = 'DENY';
  await cachePodA.bumpPolicyEpoch('5');

  // Both Pod A and Pod B must ignore stale sda:abac:compiled:0:6 and immediately evaluate DENY under epoch 1
  const r2 = await abacPodA.evaluate(evalInput);
  const r3 = await abacPodB.evaluate(evalInput);
  assert.equal(r2.decision, 'DENY');
  assert.equal(r3.decision, 'DENY');
  assert.ok(sharedRedisStore.has('sda:abac:compiled:1:6'));

  // Constructor backward compatibility: new PolicyCache(config, mockRedis) without stateStore still works
  const standaloneCache = new PolicyCache(makeMinimalConfig({ NODE_ENV: 'test' }), makeMockRedis());
  await standaloneCache.put({ version: '1', definitions: {}, rules: [] });
  assert.equal((await standaloneCache.get('1'))?.version, '1');
  assert.equal(ABAC_POLICY_EPOCH_NAMESPACE, 'abac-policy');
});

test('BUG-052 — Ownership transfer blocks self-transfer, custom privileged SoD roles, missing DOCUMENT:MANAGE (even on stripped DOCUMENT_OWNER), and executes atomic cleanup with department-scoped SSE', async () => {
  const docId = randomUUID();
  const baseDoc = {
    id: docId,
    owner_id: 10n,
    department_id: 7n,
    status: 'ACTIVE',
    title: 'Spec',
    document_code: 'DOC-052',
    version: 1,
  };
  const actor = { userId: 10n, username: 'owner1', roles: ['DOCUMENT_OWNER'], mfa: true };
  const ctx = { ip: '10.0.0.1', correlationId: randomUUID(), userAgent: 'test-agent' };
  const audit = { record: async () => {} };
  const cache = {
    invalidated: [],
    invalidateUser: async (uid) => {
      cache.invalidated.push(uid);
    },
  };

  // 1. Self-transfer blocked with 400
  await assert.rejects(
    () =>
      executeTransferDocumentOwner({
        database: { document: { findUnique: async () => baseDoc } },
        authorization: {},
        cache,
        audit,
        documentId: docId,
        input: { newOwnerId: 10n, reason: 'Self transfer attempt' },
        principal: actor,
        context: ctx,
      }),
    (err) => err.status === 400,
  );

  // 2. Custom privileged SoD role blocked with 403 TECHNICAL_ADMIN_CANNOT_OWN
  await assert.rejects(
    () =>
      executeTransferDocumentOwner({
        database: {
          document: { findUnique: async () => baseDoc },
          user: { findUnique: async () => ({ id: 20n, status: 'ACTIVE', department_id: 7n }) },
          department: { findFirst: async () => ({ id: 7n }) },
          userRole: {
            findMany: async () => [
              {
                roles: {
                  code: 'CUSTOM_AUDIT_HELPER',
                  role_permissions: [
                    {
                      permissions: { code: 'USER_MANAGE', resource_type: 'USER', action: 'MANAGE' },
                    },
                  ],
                },
              },
            ],
          },
        },
        authorization: {},
        cache,
        audit,
        documentId: docId,
        input: { newOwnerId: 20n, reason: 'Bypass via custom admin role' },
        principal: actor,
        context: ctx,
      }),
    (err) => err.response?.errorCode === AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
  );

  // 3. DOCUMENT_OWNER role with DOCUMENT_MANAGE stripped in role_permissions MUST be blocked
  await assert.rejects(
    () =>
      executeTransferDocumentOwner({
        database: {
          document: { findUnique: async () => baseDoc },
          user: { findUnique: async () => ({ id: 21n, status: 'ACTIVE', department_id: 7n }) },
          department: { findFirst: async () => ({ id: 7n }) },
          userRole: {
            findMany: async () => [
              {
                roles: {
                  code: 'DOCUMENT_OWNER',
                  role_permissions: [
                    {
                      permissions: {
                        code: 'DOCUMENT_VIEW',
                        resource_type: 'DOCUMENT',
                        action: 'VIEW',
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
        authorization: {},
        cache,
        audit,
        documentId: docId,
        input: { newOwnerId: 21n, reason: 'Stripped owner cannot manage' },
        principal: actor,
        context: ctx,
      }),
    (err) => err.response?.errorCode === AppErrorCode.DOCUMENT_ACCESS_DENIED,
  );

  // 4. Valid transfer runs in 1 transaction, revokes grants, closes former owner sessions, cancels new owner pending request, awaits cache invalidation, and emits targetDepartmentId
  let txUsed = false;
  let cancelledPending = false;
  let closedFormerSessions = 0;
  const publishedEvents = [];
  const mockTx = {
    $queryRawUnsafe: async () => [{ id: docId }],
    document: {
      findUnique: async () => baseDoc,
      update: async () => ({ ...baseDoc, owner_id: 22n }),
    },
    user: {
      findUnique: async () => ({
        id: 22n,
        status: 'ACTIVE',
        department_id: 7n,
        username: 'owner2',
      }),
    },
    department: { findFirst: async () => ({ id: 7n }) },
    userRole: {
      findMany: async () => [
        {
          roles: {
            code: 'DOCUMENT_OWNER',
            role_permissions: [
              {
                permissions: {
                  code: 'DOCUMENT_MANAGE',
                  resource_type: 'DOCUMENT',
                  action: 'MANAGE',
                },
              },
            ],
          },
        },
      ],
    },
    documentClassificationHistory: {
      findFirst: async () => ({ classification_levels: { rank: 3 } }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 3 },
      }),
    },
    accessGrant: {
      findMany: async () => [
        { id: 'g-old', principal_type: 'USER', principal_user_id: 10n },
        { id: 'g-new', principal_type: 'USER', principal_user_id: 22n },
      ],
      update: async () => ({}),
    },
    accessSession: {
      updateMany: async () => {
        closedFormerSessions += 1;
        return { count: 1 };
      },
    },
    accessRequest: {
      updateMany: async () => {
        cancelledPending = true;
        return { count: 1 };
      },
    },
  };

  await executeTransferDocumentOwner({
    database: {
      $transaction: async (fn) => {
        txUsed = true;
        return fn(mockTx);
      },
    },
    authorization: {
      effectiveGrants: async () => [
        {
          code: 'DOCUMENT_MANAGE',
          resource: 'DOCUMENT',
          action: 'MANAGE',
          scopeDepartmentId: null,
        },
      ],
    },
    cache,
    audit,
    realtime: { publish: (ev) => publishedEvents.push(ev) },
    documentId: docId,
    input: { newOwnerId: 22n, reason: 'Handover to new owner' },
    principal: actor,
    context: ctx,
  });

  assert.equal(txUsed, true);
  assert.equal(cancelledPending, true);
  assert.ok(closedFormerSessions >= 1);
  assert.deepEqual(cache.invalidated, [10n, 22n]);
  const sessionEvent = publishedEvents.find((e) => e.type === 'ACCESS_SESSION_UPDATED');
  assert.equal(sessionEvent?.targetDepartmentId, '7');
});

test('BUG-053 — Derivative PDF cache invalidates immediately on classification upgrade and updates existing watermark_instances in place without duplicate unique key', async () => {
  const stateStore = new DistributedStateService();
  const bucketObjects = new Map();
  let deletedKey = null;
  const storage = {
    documentsBucket: 'docs',
    derivativesBucket: 'derivatives',
    async putObject(b, k, buf) {
      bucketObjects.set(`${b}:${k}`, buf);
    },
    async getObject(b, k) {
      const buf = bucketObjects.get(`${b}:${k}`);
      if (!buf) throw new Error('not found');
      return buf;
    },
    async deleteObject(b, k) {
      deletedKey = k;
      bucketObjects.delete(`${b}:${k}`);
    },
  };

  const pdfBytes = await createMinimalPdfBuffer();
  const sessionId = randomUUID();
  await storeCachedSessionPdf({
    storage,
    stateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: 1n,
    pdfBuffer: pdfBytes,
    pageCount: 1,
    watermarkToken: undefined,
    outputSha256Hash: 'old-hash',
    classificationContext: {
      classificationLevelId: '1',
      classificationName: 'INTERNAL',
      requireWatermark: false,
      documentCode: 'DOC-053',
    },
  });

  // Upgrading to TOP_SECRET with requireWatermark=true MUST evict stale cache
  const miss = await tryLoadCachedSessionPdf({
    storage,
    stateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: 1n,
    expectedContext: {
      classificationLevelId: '4',
      classificationName: 'TOP_SECRET',
      requireWatermark: true,
      documentCode: 'DOC-053',
    },
  });
  assert.equal(miss, null);
  assert.ok(deletedKey?.includes(sessionId));

  // Verify executeWatermarkedPreview updates existing WatermarkInstance in place (keeping token)
  const existingToken = `WM-${'ab'.repeat(24)}`;
  let updatedRecord = null;
  let createdCount = 0;
  bucketObjects.set('docs:v1.enc', pdfBytes);

  const mockDb = {
    accessSession: {
      findUnique: async () => ({
        id: sessionId,
        status: 'ACTIVE',
        user_id: 1n,
        access_grant_id: 'g-1',
        ip_address: '10.0.0.1',
        user_agent: 'UA',
        document_versions: {
          id: 1n,
          document_id: 'doc-1',
          storage_key: 'v1.enc',
          encryption_key_ref: 'k1',
          original_filename: 'report.pdf',
          document: {
            id: 'doc-1',
            document_code: 'DOC-053',
            title: 'Upgraded Doc',
            classification_history: [
              {
                classification_level_id: 4n,
                classification_levels: {
                  id: 4n,
                  code: 'TOP_SECRET',
                  name: 'Tuyệt mật',
                  rank: 4,
                  require_watermark: true,
                },
              },
            ],
          },
        },
      }),
      update: async () => ({}),
    },
    watermarkInstance: {
      findFirst: async () => ({
        id: 'wm-row-1',
        watermark_token: existingToken,
        watermark_config_id: 1n,
        rendered_text: 'OLD INTERNAL TEXT',
        output_sha256_hash: 'old-hash',
      }),
      update: async ({ where, data }) => {
        updatedRecord = { where, data };
        return data;
      },
    },
    user: {
      findUnique: async () => ({
        id: 1n,
        username: 'alice',
        full_name: 'Alice',
        employee_code: 'E1',
      }),
    },
  };

  const fs = await import('node:fs/promises');
  const os = await import('node:os');
  const path = await import('node:path');
  const tmpFile = path.join(os.tmpdir(), `sda-bug053-${randomUUID()}.pdf`);
  await fs.writeFile(tmpFile, pdfBytes);

  await executeWatermarkedPreview({
    database: mockDb,
    pep: { enforceSessionPolicy: async () => ({ watermarkRequired: true }) },
    storage,
    encryption: {
      decryptToTempFile: async () => ({
        tempFilePath: tmpFile,
        cleanup: async () => fs.unlink(tmpFile).catch(() => {}),
      }),
    },
    officeConverter: {},
    watermarkEngine: {
      getWatermarkConfig: async () => ({ id: 4n, include_qr_code: true }),
      applyWatermarkToPdf: async (_buf, _u, _d, _c, token) => ({
        watermarkedBuffer: pdfBytes,
        watermarkToken: token,
        outputSha256Hash: 'new-top-secret-hash',
        renderedText: 'TOP SECRET WATERMARK',
        pageCount: 1,
      }),
      recordWatermarkInstance: async () => {
        createdCount += 1;
      },
    },
    grantsService: { assertGrantValidForAccess: async () => {} },
    audit: { record: async () => {} },
    stateStore,
    config: undefined,
    documentId: 'doc-1',
    sessionId,
    pageNumber: undefined,
    principal: { userId: 1n, username: 'alice', roles: ['DOCUMENT_READER'], mfa: true },
    context: { ip: '10.0.0.1', userAgent: 'UA', correlationId: randomUUID() },
  });

  assert.equal(createdCount, 0, 'Must NOT insert duplicate WatermarkInstance');
  assert.equal(updatedRecord?.where?.id, 'wm-row-1');
  assert.equal(updatedRecord?.data?.output_sha256_hash, 'new-top-secret-hash');
  assert.equal(updatedRecord?.data?.watermark_config_id, 4n);
});

test('BUG-054 — PEP performs read-only owner check before ABAC deny (zero DB writes) and provisions owner SYSTEM grant with CHECK 23514 fields, retention clamp, and advisory lock', async () => {
  let grantWrites = 0;
  const mockDb = {
    document: {
      findUnique: async () => ({
        id: 'doc-054',
        owner_id: 5n,
        department_id: 1n,
        status: 'ACTIVE',
        title: 'Owner Doc',
        document_code: 'DOC-054',
        retention_until: new Date('2027-01-01T00:00:00Z'),
        current_version: { id: 1n, version_no: 1, scan_status: 'CLEAN' },
        classification_history: [
          {
            classification_levels: { rank: 2, allow_download: true, require_watermark: true },
            business_categories: { code: 'GEN' },
          },
        ],
      }),
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userRole: { findMany: async () => [] },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 3 },
      }),
      findMany: async () => [],
    },
    accessGrant: {
      findFirst: async () => null,
      create: async () => {
        grantWrites += 1;
        return {};
      },
    },
  };

  const pep = new DocumentPepService(
    { evaluate: async () => ({ decision: 'DENY', reasonCode: 'EXPLICIT_DENY', obligations: [] }) },
    {},
    { record: async () => {} },
    mockDb,
  );

  await assert.rejects(
    () =>
      pep.enforceAccess(
        'doc-054',
        { userId: 5n, username: 'owner5', roles: ['DOCUMENT_OWNER'], mfa: true },
        { ip: '10.0.0.1', userAgent: 'UA', correlationId: randomUUID() },
        { action: 'VIEW' },
      ),
    (err) => err.response?.errorCode === AppErrorCode.POLICY_DENIED,
  );
  assert.equal(grantWrites, 0, 'Must NOT write access_grants when ABAC PDP denies');

  // Verify ensurePermittedOwnerSystemGrant satisfies CHECK 23514, clamps retention_until, uses advisory lock & skipDuplicates
  const lockCalls = [];
  const staleUpdates = [];
  let createdGrantData = null;
  const retentionCutoff = new Date('2026-12-01T00:00:00Z');
  const now = new Date('2026-11-26T00:00:00Z');

  const txMock = {
    $executeRawUnsafe: async (sql, ...args) => {
      lockCalls.push({ sql, args });
    },
    accessGrant: {
      findFirst: async () => null,
      findMany: async () => [
        { id: 'future-grant-1', valid_until: new Date('2027-02-01T00:00:00Z') },
      ],
      update: async ({ where, data }) => {
        staleUpdates.push({ where, data });
      },
      create: async ({ data }) => {
        createdGrantData = data;
        return data;
      },
    },
  };

  const grantId = await ensurePermittedOwnerSystemGrant({
    database: { $transaction: async (fn) => fn(txMock) },
    documentId: 'doc-054',
    userId: 5n,
    action: 'VIEW',
    now,
    classAllowDownload: true,
    documentRetentionUntil: retentionCutoff,
  });

  assert.ok(grantId);
  assert.ok(lockCalls.some((c) => c.sql.includes('pg_advisory_xact_lock')));
  assert.equal(staleUpdates[0].data.status, 'REVOKED');
  assert.equal(staleUpdates[0].data.revoked_by, 5n);
  assert.ok(staleUpdates[0].data.revoked_at instanceof Date);
  assert.ok(typeof staleUpdates[0].data.revoke_reason === 'string');
  assert.equal(createdGrantData.source, 'SYSTEM');
  assert.equal(createdGrantData.valid_until.getTime(), retentionCutoff.getTime());
  assert.equal(createdGrantData.access_grant_permissions.createMany.skipDuplicates, true);
});

test('BUG-055 — Watermark rendering preserves recipient prefix & full 48-hex token without truncation, and updateConfig requires {username} or {fullName}', async () => {
  const fullToken = `WM-${'0123456789abcdef'.repeat(3)}`;
  const user = { id: 7n, username: 'alice', fullName: 'Alice Nguyen', employeeCode: 'NV-7' };
  const topSecretDoc = {
    id: 'doc-ts',
    documentCode: 'TS-01',
    title: 'Secret',
    classificationName: 'Tuyệt mật',
    classificationCode: 'TOP_SECRET',
    classificationRank: 4,
    requireWatermark: true,
  };

  // Template omitting {username}/{fullName} must prepend identity instead of wiping {watermarkToken}
  const rendered = formatForensicWatermarkText(
    'TOP SECRET | {documentCode} | {watermarkToken}',
    user,
    topSecretDoc,
    fullToken,
    new Date('2026-11-26T00:00:00Z'),
    { includeQrCode: false },
  );
  assert.ok(rendered.startsWith('Alice Nguyen (NV-7) | '));
  assert.ok(rendered.includes(fullToken));

  // Long text > 1000 chars on rank >= 3 with QR disabled must NEVER truncate 48-hex token
  const longRendered = formatForensicWatermarkText(
    `${'X'.repeat(1100)} | {username}`,
    user,
    topSecretDoc,
    fullToken,
    new Date('2026-11-26T00:00:00Z'),
    { includeQrCode: false },
  );
  assert.ok(longRendered.length <= 1000);
  assert.ok(longRendered.endsWith(fullToken));

  // Saving config without {username} or {fullName} throws BadRequestException
  assert.throws(() => assertWatermarkTemplateHasRecipientIdentity('CONFIDENTIAL | {documentCode}'));
  assert.doesNotThrow(() =>
    assertWatermarkTemplateHasRecipientIdentity('{username} | {shortToken}'),
  );

  const svc = new WatermarksService({
    watermarkConfig: {
      findUnique: async () => ({
        id: 1n,
        include_qr_code: true,
        template_text: '{username} | {shortToken}',
        classification_level_id: null,
        classification_levels: null,
      }),
    },
  });
  await assert.rejects(
    () => svc.updateConfig(1n, { templateText: 'NO IDENTITY HERE {shortToken}' }),
    {
      status: 400,
    },
  );
});

test('BUG-056 — Retention scan isolates HTTP callers strictly to own ACTIVE/ARCHIVED docs within clearance and avoids audit spam on repeated runs', async () => {
  const auditEvents = [];
  const storedNotifs = [];
  const mockDb = {
    document: {
      findMany: async () => [
        {
          id: 'own-ok',
          document_code: 'D-1',
          title: 'Own Internal',
          status: 'ACTIVE',
          owner_id: 10n,
          department_id: 1n,
          retention_until: new Date('2026-12-01T00:00:00Z'),
          classification_history: [{ classification_levels: { rank: 1 } }],
        },
        {
          id: 'other-owner-doc',
          document_code: 'D-2',
          title: 'Other Owner Secret',
          status: 'ACTIVE',
          owner_id: 99n,
          department_id: 1n,
          retention_until: new Date('2026-12-01T00:00:00Z'),
          classification_history: [{ classification_levels: { rank: 1 } }],
        },
        {
          id: 'own-top-secret',
          document_code: 'D-3',
          title: 'Own Top Secret Above Clearance',
          status: 'ACTIVE',
          owner_id: 10n,
          department_id: 1n,
          retention_until: new Date('2026-12-01T00:00:00Z'),
          classification_history: [{ classification_levels: { rank: 4 } }],
        },
        {
          id: 'own-draft',
          document_code: 'D-4',
          title: 'Own Draft',
          status: 'DRAFT',
          owner_id: 10n,
          department_id: 1n,
          retention_until: new Date('2026-12-01T00:00:00Z'),
          classification_history: [{ classification_levels: { rank: 1 } }],
        },
      ],
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 2 },
      }),
    },
    notification: {
      findMany: async () => storedNotifs,
      createMany: async ({ data }) => {
        storedNotifs.push(...data);
        return { count: data.length };
      },
    },
    securityAlert: { findMany: async () => [], createMany: async () => ({ count: 0 }) },
  };

  const caller = { userId: 10n, username: 'owner10', roles: ['DOCUMENT_OWNER'], mfa: true };
  const first = await executeCheckRetentionWarnings({
    database: mockDb,
    authorization: { hasPermission: async () => true },
    audit: { record: async (ev) => auditEvents.push(ev) },
    daysThreshold: 60,
    principal: caller,
  });

  assert.deepEqual(
    first.warnings.map((w) => w.documentId),
    ['own-ok'],
  );
  assert.equal(auditEvents.length, 1);

  // Second call on same day must NOT emit duplicate audit log
  await executeCheckRetentionWarnings({
    database: mockDb,
    authorization: { hasPermission: async () => true },
    audit: { record: async (ev) => auditEvents.push(ev) },
    daysThreshold: 60,
    principal: caller,
  });
  assert.equal(auditEvents.length, 1, 'Repeated retention check must not spam audit_logs');
});

test('BUG-057 — Session UA/IP binding is one-way fail-closed and policyVersion / subject change forces immediate ABAC re-evaluation preserving started_at expiry anchor', async () => {
  const sessionId = randomUUID();
  const stateStore = new DistributedStateService();
  const startedAt = new Date('2026-11-26T00:00:00Z');
  const now = new Date('2026-11-26T00:05:00Z');

  // 1. Missing caller User-Agent when session is bound to UA must be rejected (one-way fail-closed)
  await assert.rejects(
    () =>
      loadValidatedDeliverySession({
        database: {
          accessSession: {
            findUnique: async () => ({
              id: sessionId,
              status: 'ACTIVE',
              user_id: 1n,
              ip_address: '10.0.0.5',
              user_agent: 'Mozilla/5.0 BoundAgent',
              document_versions: { document_id: 'doc-57' },
            }),
          },
        },
        pep: { enforceSessionPolicy: async () => ({}) },
        sessionId,
        documentId: 'doc-57',
        principal: { userId: 1n, username: 'u1', roles: ['DOCUMENT_READER'], mfa: true },
        context: { ip: '10.0.0.5', userAgent: undefined, correlationId: randomUUID() },
        now,
        requireDownloadPolicy: false,
      }),
    (err) => err.status === 403,
  );

  // 2. Policy version bump forces immediate ABAC re-evaluation even within 60-min cache TTL
  await stateStore.putEphemeral(
    'session-policy',
    sessionId,
    {
      grantedAction: 'VIEW',
      forbidDownload: false,
      watermarkRequired: true,
      expiresAtMs: startedAt.getTime() + 10 * 60_000,
      maxSessionMinutes: 10,
      ipAddress: '10.0.0.5',
      userAgent: 'Mozilla/5.0 BoundAgent',
      policyVersion: '1',
      abacEpoch: 0,
      userEpoch: 0,
      subjectSnapshot: { employmentStatus: 'ACTIVE', clearanceRank: 2, departmentId: '1' },
    },
    60 * 60_000,
  );

  let abacCalls = 0;
  await assert.rejects(
    () =>
      resolveAndEnforceSessionPolicy({
        session: {
          id: sessionId,
          status: 'ACTIVE',
          user_id: 1n,
          ip_address: '10.0.0.5',
          user_agent: 'Mozilla/5.0 BoundAgent',
          started_at: startedAt,
          document_versions: {
            document_id: 'doc-57',
            document: {
              id: 'doc-57',
              owner_id: 2n,
              department_id: 1n,
              status: 'ACTIVE',
              classification_history: [
                { classification_levels: { rank: 2, require_watermark: true } },
              ],
            },
          },
        },
        requiredAction: 'VIEW',
        principal: { userId: 1n, username: 'u1', roles: ['DOCUMENT_READER'], mfa: true },
        context: {
          ip: '10.0.0.5',
          userAgent: 'Mozilla/5.0 BoundAgent',
          correlationId: randomUUID(),
        },
        now,
        stateStore,
        database: {
          accessSession: {
            findUnique: async () => ({
              id: sessionId,
              status: 'ACTIVE',
              user_id: 1n,
              ip_address: '10.0.0.5',
              user_agent: 'Mozilla/5.0 BoundAgent',
            }),
          },
          user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
          userAttributeAssignment: {
            findFirst: async () => ({
              attribute_definitions: { is_active: true },
              attribute_options: { is_active: true, numeric_rank: 2 },
            }),
            findMany: async () => [],
          },
        },
        abac: {
          getCurrentPolicyVersion: async () => '2',
          evaluate: async () => {
            abacCalls += 1;
            return {
              decision: 'DENY',
              reasonCode: 'NEW_DENY_RULE',
              obligations: [],
              policyVersion: '2',
            };
          },
        },
      }),
    (err) => err.response?.errorCode === AppErrorCode.POLICY_DENIED,
  );
  assert.equal(abacCalls, 1);
});

test('BUG-058 — reverifyRedeemedTicketState checks live auth_sessions, live RBAC DOCUMENT:DOWNLOAD, SoD, clearance, and UA before returning fresh livePrincipal', async () => {
  const now = new Date('2026-11-26T12:00:00Z');
  const baseEntry = {
    documentId: 'doc-58',
    sessionId: 'acc-sess-1',
    userId: 50n,
    principal: {
      userId: 50n,
      sessionId: 'auth-sess-1',
      username: 'stale-name',
      roles: ['DOCUMENT_READER'],
      mfa: true,
    },
    issuedIp: '10.0.0.10',
    issuedUa: 'Browser/1.0',
    createdAt: now.getTime() - 1_000,
    expiresAt: now.getTime() + 60_000,
  };
  const ctx = { ip: '10.0.0.10', userAgent: 'Browser/1.0', correlationId: randomUUID() };

  // 1. Revoked / expired authSession rejected
  await assert.rejects(
    () =>
      reverifyRedeemedTicketState({
        database: {
          authSession: { findFirst: async () => ({ id: 'auth-sess-1', status: 'REVOKED' }) },
        },
        grantsService: {},
        entry: baseEntry,
        context: ctx,
        now,
      }),
    (err) => err.response?.errorCode === AppErrorCode.SESSION_TERMINATED,
  );

  // 2. Live RBAC stripped DOCUMENT:DOWNLOAD rejected even though snapshot had DOCUMENT_READER
  const liveDb = {
    authSession: {
      findFirst: async () => ({
        id: 'auth-sess-1',
        status: 'ACTIVE',
        expires_at: new Date(now.getTime() + 3_600_000),
        last_seen_at: now,
        mfa_verified_at: now,
      }),
    },
    accessSession: {
      findUnique: async () => ({
        id: 'acc-sess-1',
        status: 'ACTIVE',
        user_id: 50n,
        access_grant_id: 'g-58',
        ip_address: '10.0.0.10',
        user_agent: 'Browser/1.0',
      }),
    },
    accessGrant: {
      findUnique: async () => ({
        id: 'g-58',
        status: 'ACTIVE',
        valid_from: new Date(now.getTime() - 1_000),
        valid_until: new Date(now.getTime() + 3_600_000),
      }),
    },
    user: {
      findUnique: async () => ({
        status: 'ACTIVE',
        locked_until: null,
        username: 'fresh-name',
        department_id: 3n,
      }),
    },
    document: {
      findUnique: async () => ({
        id: 'doc-58',
        status: 'ACTIVE',
        department_id: 3n,
        classification_history: [{ classification_levels: { rank: 2 } }],
      }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 2 },
      }),
    },
  };

  await assert.rejects(
    () =>
      reverifyRedeemedTicketState({
        database: liveDb,
        grantsService: { assertGrantValidForAccess: async () => {} },
        authorization: {
          effectiveGrants: async () => [
            {
              roleCode: 'DOCUMENT_READER',
              code: 'DOCUMENT_VIEW',
              resource: 'DOCUMENT',
              action: 'VIEW',
            },
          ],
          hasPermission: async () => false,
        },
        entry: baseEntry,
        context: ctx,
        now,
      }),
    (err) => err.response?.errorCode === AppErrorCode.DOCUMENT_ACCESS_DENIED,
  );

  // 3. Valid live state returns refreshed livePrincipal
  const refreshed = await reverifyRedeemedTicketState({
    database: liveDb,
    grantsService: { assertGrantValidForAccess: async () => {} },
    authorization: {
      effectiveGrants: async () => [
        {
          roleCode: 'DOCUMENT_OWNER',
          code: 'DOCUMENT_DOWNLOAD',
          resource: 'DOCUMENT',
          action: 'DOWNLOAD',
        },
      ],
      hasPermission: async () => true,
    },
    entry: baseEntry,
    context: ctx,
    now,
  });
  assert.equal(refreshed.username, 'fresh-name');
  assert.deepEqual(refreshed.roles, ['DOCUMENT_OWNER']);
  assert.equal(refreshed.departmentId, 3n);
});

test('BUG-059 — OOXML extractor closes oversized XML entries without hanging, reads all sheets/slides, wraps long tokens, and production fails closed with 503 OFFICE_CONVERTER_UNAVAILABLE', async () => {
  // 1. Oversized XML entry (>5 MiB) resolves immediately without 10s hang
  const oversizedXml = `<w:document><w:body><w:p>${'A'.repeat(5 * 1024 * 1024 + 2048)}</w:p></w:body></w:document>`;
  const zipBuf = createZipBuffer([
    { name: 'word/document.xml', content: Buffer.from(oversizedXml, 'utf8') },
  ]);
  const start = Date.now();
  const extracted = await extractOfficeFallbackText(zipBuf, 'oversized.docx');
  assert.ok(Date.now() - start < 4_000, 'Oversized XML must settle rapidly without hanging yauzl');
  assert.equal(extracted, 'Document body is empty.');

  // 2. XLSX reads ALL sheets & PPTX reads > 20 slides
  const multiSheetXlsx = createZipBuffer([
    {
      name: 'xl/sharedStrings.xml',
      content: Buffer.from('<sst><si><t>Alpha</t></si><si><t>Beta</t></si></sst>'),
    },
    {
      name: 'xl/worksheets/sheet1.xml',
      content: Buffer.from(
        '<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>',
      ),
    },
    {
      name: 'xl/worksheets/sheet2.xml',
      content: Buffer.from(
        '<worksheet><sheetData><row><c t="s"><v>1</v></c></row></sheetData></worksheet>',
      ),
    },
  ]);
  const xlsxText = await extractOfficeFallbackText(multiSheetXlsx, 'multi.xlsx');
  assert.ok(xlsxText.includes('Alpha') && xlsxText.includes('Beta'));

  const slideEntries = [];
  for (let i = 1; i <= 25; i++) {
    slideEntries.push({
      name: `ppt/slides/slide${i}.xml`,
      content: Buffer.from(`<p:sld><a:p><a:t>SlideMarker${i}</a:t></a:p></p:sld>`),
    });
  }
  const pptxText = await extractOfficeFallbackText(createZipBuffer(slideEntries), 'deck.pptx');
  assert.ok(pptxText.includes('SlideMarker25'), 'Must not truncate PPTX at 20 slides');

  // 3. Long unbroken word > 90 chars is wrapped without losing tail
  const longToken = `${'Z'.repeat(110)}TAILMARKER`;
  const wrappedPdf = await renderSanitizedTextToPdf('long.docx', longToken, 10);
  assert.ok(wrappedPdf.subarray(0, 4).toString('ascii') === '%PDF');

  // 4. Production fail-closed 503 when gotenbergEnabled=true and converter unavailable
  const prodConverter = new OfficeConverterService(
    makeMinimalConfig({
      NODE_ENV: 'production',
      GOTENBERG_ENABLED: true,
      GOTENBERG_URL: 'http://127.0.0.1:1',
    }),
  );
  const minimalDocx = createZipBuffer([
    {
      name: '[Content_Types].xml',
      content: Buffer.from('<?xml version="1.0"?><Types></Types>'),
    },
    {
      name: 'word/document.xml',
      content: Buffer.from('<w:document><w:body><w:p><w:t>Hello</w:t></w:p></w:body></w:document>'),
    },
  ]);
  await assert.rejects(
    () => prodConverter.convertOfficeToPdf(minimalDocx, 'prod.docx', { timeoutMs: 2_000 }),
    (err) =>
      err.status === 503 && err.response?.errorCode === AppErrorCode.OFFICE_CONVERTER_UNAVAILABLE,
  );
});

test('BUG-060 — AuditRedactionService.sanitizeIp matches PostgreSQL inet_out 1-to-1 across RFC 5952 IPv6 and IPv4-mapped addresses', async () => {
  const redactor = new AuditRedactionService();
  const pg = new PGlite();
  try {
    const vectors = [
      '127.0.0.1',
      '2001:0DB8::1',
      '2001:0db8:0000:0000:0000:0000:0000:0001',
      '2001:db8:0:1:1:1:1:1',
      '2001:db8:0:0:1:0:0:1',
      '2001:db8:0:0:1:0:0:0',
      '::ffff:127.0.0.1',
      '::FFFF:127.0.0.1',
      '0:0:0:0:0:ffff:7f00:0001',
      '::ffff:0.0.0.0',
      '::192.168.1.1',
      '::1',
      '::',
      '::2',
    ];
    for (const ip of vectors) {
      const res = await pg.query('SELECT $1::inet AS inet_text', [ip]);
      assert.equal(
        redactor.sanitizeIp(ip),
        res.rows[0].inet_text,
        `sanitizeIp(${ip}) must match PostgreSQL inet_out`,
      );
      assert.equal(canonicalizePostgresInetAddress(ip), res.rows[0].inet_text);
    }
    // Never converts ::ffff:127.0.0.1 into WHATWG URL ::ffff:7f00:1
    assert.equal(redactor.sanitizeIp('::ffff:127.0.0.1'), '::ffff:127.0.0.1');
    assert.equal(redactor.sanitizeIp('fe80::1%eth0'), 'fe80::1');
  } finally {
    await pg.close();
  }
});

test('BUG-061 — SOC Alerts & Incidents enforce date bounds, ACTIVE assignee, required ACTIVE submit recipient(s), VIEW scope for createIncident, closed-alert assign block, and atomic SQL note append', async () => {
  // (1) Date range bounds
  const bounds = resolveSocDateRangeBounds('2026-11-01', '2026-11-26');
  assert.equal(bounds.gte.toISOString(), '2026-11-01T00:00:00.000Z');
  assert.equal(bounds.lte.toISOString(), '2026-11-26T23:59:59.999Z');
  assert.throws(() => resolveSocDateRangeBounds('2026-11-27', '2026-11-26'), { status: 400 });

  const socActor = { userId: 2n, username: 'soc1', roles: ['SECURITY_OFFICER'], mfa: true };

  // (2) addIncidentAction rejects non-ACTIVE assignee
  await assert.rejects(
    () =>
      executeAddIncidentAction(
        {
          incidentReport: { findUnique: async () => ({ id: 'inc-1', status: 'DRAFT' }) },
          user: { findUnique: async () => ({ id: 88n, status: 'DISABLED' }) },
        },
        undefined,
        'inc-1',
        { actionType: 'CONTAIN', recommendation: 'Disable token', assignedTo: 88n },
        socActor,
      ),
    (err) => err.response?.errorCode === AppErrorCode.USER_NOT_ACTIVE,
  );

  // (3) submitIncident requires at least one recipient and notifies BOTH owner and admin
  await assert.rejects(
    () =>
      executeSubmitIncidentReport(
        { incidentReport: { findUnique: async () => ({ id: 'inc-1', status: 'DRAFT' }) } },
        undefined,
        'inc-1',
        {},
        socActor,
      ),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );

  const notifiedRecipients = [];
  const incId = randomUUID();
  const incDb = {
    incidentReport: {
      findUnique: async () => ({
        id: incId,
        incident_code: 'INC-2026-ABCDEF',
        alert_id: null,
        title: 'Leak',
        summary: 'Summary text',
        findings: 'Root cause',
        impact_assessment: 'High',
        status: 'DRAFT',
        prepared_by: 2n,
        submitted_to_owner: 10n,
        submitted_to_admin: 20n,
        created_at: new Date(),
        submitted_at: null,
        closed_at: null,
        incident_actions: [],
      }),
      update: async () => ({ id: incId }),
    },
    user: {
      findUnique: async ({ where }) => ({ id: where.id, status: 'ACTIVE', department_id: 1n }),
    },
  };
  const incSvc = new IncidentsService(incDb, undefined, undefined, undefined, {
    sendNotification: async (opts) => {
      notifiedRecipients.push(opts.recipientId);
      return { isDuplicate: false };
    },
  });
  await incSvc.submitIncidentReport(
    incId,
    { submittedToOwner: 10n, submittedToAdmin: 20n },
    socActor,
  );
  assert.deepEqual(notifiedRecipients, [10n, 20n]);

  // (4) createIncidentReport checks alert scope with VIEW (not MANAGE)
  let checkedAction = null;
  const scopedIncSvc = new IncidentsService(
    {
      securityAlert: {
        findUnique: async () => ({ id: 'a-1', detected_user_id: null, document_id: 'd-1' }),
      },
      document: { findUnique: async () => ({ department_id: 3n }) },
      incidentReport: {
        create: async ({ data }) => ({ id: data.id }),
        findUnique: async ({ where }) => ({
          id: where.id,
          incident_code: 'INC-2026-123456',
          alert_id: 'a-1',
          title: 'Incident',
          summary: 'Summary long enough',
          findings: null,
          impact_assessment: null,
          status: 'DRAFT',
          prepared_by: 2n,
          submitted_to_owner: null,
          submitted_to_admin: null,
          created_at: new Date(),
          submitted_at: null,
          closed_at: null,
          incident_actions: [],
        }),
      },
    },
    undefined,
    {
      visibleDepartmentIds: async (_actor, _res, action) => {
        if (!checkedAction) checkedAction = action;
        return [3n];
      },
    },
  );
  await scopedIncSvc.createIncidentReport(
    { alertId: 'a-1', title: 'Incident', summary: 'Summary long enough' },
    socActor,
  );
  assert.equal(checkedAction, 'VIEW');

  // (5) assignAlert blocks RESOLVED alert & non-ACTIVE user, and (6) addAlertNote uses atomic SQL CASE
  let rawSqlExecuted = '';
  const alertSvc = new SecurityAlertsService({
    securityAlert: {
      findUnique: async ({ where }) =>
        where.id === 'closed-1'
          ? { id: 'closed-1', status: 'RESOLVED', description: 'done', detected_at: new Date() }
          : { id: 'open-1', status: 'OPEN', description: 'base', detected_at: new Date() },
    },
    user: { findUnique: async () => ({ id: 9n, status: 'LOCKED' }) },
    $executeRawUnsafe: async (sql) => {
      rawSqlExecuted = sql;
      return 1;
    },
  });
  await assert.rejects(() => alertSvc.assignAlert('closed-1', 2n, socActor), { status: 400 });
  await assert.rejects(() => alertSvc.assignAlert('open-1', 9n, socActor), { status: 400 });
  await alertSvc.addAlertNote('open-1', 'Investigating source IP', socActor);
  assert.match(rawSqlExecuted, /UPDATE public\.security_alerts/u);
  assert.match(rawSqlExecuted, /SET description = CASE/u);
});

test('BUG-062 — NotificationsController uses @AllowAuthenticatedSelf and NotificationsService deduplicates before inserting notifications or publishing SSE', async () => {
  const allowSelf = Reflect.getMetadata(ALLOW_AUTHENTICATED_SELF_METADATA, NotificationsController);
  assert.equal(allowSelf, true);

  let notifCreates = 0;
  let sseEmits = 0;
  const outboxKeys = new Set();
  const notifIds = new Set();

  const service = new NotificationsService(
    {
      notificationOutbox: {
        findUnique: async ({ where }) =>
          outboxKeys.has(where.deduplication_key) ? { id: 'ob-1', status: 'PENDING' } : null,
        create: async ({ data }) => {
          outboxKeys.add(data.deduplication_key);
          return data;
        },
      },
      notification: {
        findUnique: async ({ where }) => (notifIds.has(where.id) ? { id: where.id } : null),
        create: async ({ data }) => {
          notifCreates += 1;
          notifIds.add(data.id);
          return data;
        },
      },
    },
    {
      publish: () => {
        sseEmits += 1;
      },
    },
  );

  const first = await service.sendNotification({
    recipientId: 1n,
    notificationType: 'TEST_ALERT',
    title: 'Hello',
    body: 'Body',
    channel: 'BOTH',
    deduplicationKey: 'dedup-bug-062',
  });
  const second = await service.sendNotification({
    recipientId: 1n,
    notificationType: 'TEST_ALERT',
    title: 'Hello',
    body: 'Body',
    channel: 'BOTH',
    deduplicationKey: 'dedup-bug-062',
  });

  assert.equal(first.isDuplicate, false);
  assert.ok(first.notificationId);
  assert.equal(second.isDuplicate, true);
  assert.equal(second.notificationId, undefined);
  assert.equal(notifCreates, 1);
  assert.equal(sseEmits, 1);
});

test('BUG-063 — RealtimeEventsService silently closes sockets on rbac-user invalidation (NO USER_SESSION_REVOKED), enforces expiresAtMs, and isolates SOC events by targetDepartmentId', async () => {
  const stateStore = new DistributedStateService();
  const realtime = new RealtimeEventsService(stateStore);

  const user10Frames = [];
  let user10Closed = false;
  realtime.registerClient({
    userId: '10',
    sessionId: 's-10',
    roles: ['DOCUMENT_OWNER'],
    writeFrame: (f) => {
      user10Frames.push(f);
      return true;
    },
    close: () => {
      user10Closed = true;
    },
  });

  // RBAC change must close socket silently WITHOUT emitting USER_SESSION_REVOKED
  await stateStore.bumpNamespaceEpoch('rbac-user:10');
  assert.equal(user10Closed, true);
  assert.equal(
    user10Frames.some((f) => f.includes('USER_SESSION_REVOKED')),
    false,
    'RBAC change must NOT send USER_SESSION_REVOKED frame that logs user out',
  );

  // Department-scoped SOC SSE filtering + expiresAtMs enforcement
  const dept1Frames = [];
  const dept2Frames = [];
  const expiredFrames = [];
  let expiredClosed = false;

  realtime.registerClient({
    userId: '101',
    roles: ['SECURITY_OFFICER'],
    allowedDeptIds: new Set(['1']),
    expiresAtMs: Date.now() + 60_000,
    writeFrame: (f) => {
      dept1Frames.push(f);
      return true;
    },
    close: () => {},
  });
  realtime.registerClient({
    userId: '102',
    roles: ['SECURITY_OFFICER'],
    allowedDeptIds: new Set(['2']),
    expiresAtMs: Date.now() + 60_000,
    writeFrame: (f) => {
      dept2Frames.push(f);
      return true;
    },
    close: () => {},
  });
  realtime.registerClient({
    userId: '103',
    roles: ['SECURITY_OFFICER'],
    allowedDeptIds: null,
    expiresAtMs: Date.now() - 1_000,
    writeFrame: (f) => {
      expiredFrames.push(f);
      return true;
    },
    close: () => {
      expiredClosed = true;
    },
  });

  realtime.publish({
    type: 'SECURITY_ALERT_UPDATED',
    targetRoles: ['SECURITY_OFFICER'],
    targetDepartmentId: '1',
    payload: { id: 'alert-dept-1' },
  });

  // Allow microtask local publish flush
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(dept1Frames.length, 1);
  assert.equal(dept2Frames.length, 0);
  assert.equal(expiredFrames.length, 0);
  assert.equal(expiredClosed, true);
  realtime.onModuleDestroy();
});

test('BUG-064 — Redlock degrades cleanly when failClosed: false and quorum is lost (1/3 Redis alive), while keeping defaultFailClosed = true', async () => {
  const aliveNode = {
    async set() {
      return 'OK';
    },
    async eval() {
      return 1;
    },
    async ping() {
      return 'PONG';
    },
    disconnect() {},
  };
  const deadNode = {
    async set() {
      throw new Error('ECONNREFUSED');
    },
    async eval() {
      throw new Error('ECONNREFUSED');
    },
    async ping() {
      throw new Error('ECONNREFUSED');
    },
    disconnect() {},
  };

  assert.equal(await probeQuorumRedisHealthy([aliveNode, deadNode, deadNode], 2), false);
  assert.equal(await probeQuorumRedisHealthy([aliveNode, aliveNode, deadNode], 2), true);

  const redlock = new RedlockService(
    makeMinimalConfig({ REDLOCK_RETRY_COUNT: 0, REDLOCK_RETRY_DELAY_MS: 1 }),
    [aliveNode, deadNode, deadNode],
  );

  // failClosed: false degrades to DB fallback when only 1/3 nodes alive (< quorum 2)
  const fallbackResult = await redlock.withLock(
    'res-bug-064',
    500,
    async (handle) => handle.token,
    { failClosed: false },
  );
  assert.equal(fallbackResult, 'fallback-token');

  // Default (failClosed omitted -> defaultFailClosed = true) rejects with 409 DISTRIBUTED_LOCK_TIMEOUT
  await assert.rejects(
    () => redlock.withLock('res-bug-064', 500, async () => 'never'),
    (err) => err.status === 409 && err.response?.errorCode === 'DISTRIBUTED_LOCK_TIMEOUT',
  );
});

test('BUG-065 & BUG-066 — Audit HMAC key priority ignores empty strings identically to Worker, and Export HKDF cipher is deterministic in dev/test and fails fast in production', () => {
  const envSample = {
    NODE_ENV: 'production',
    AUDIT_INTEGRITY_KEY: '   ',
    DOCUMENT_AUDIT_HMAC_KEY: '',
    AUTH_AUDIT_HMAC_KEY: 'prod-auth-audit-key-with-at-least-32-chars-0001',
    AUDIT_HMAC_KEY: 'prod-fallback-key-with-at-least-32-chars-0002',
  };
  assert.equal(
    resolvePrimaryAuditHmacKey(makeMinimalConfig(envSample)),
    resolvePrimaryAuditHmacKeyFromEnv(envSample),
  );
  assert.equal(
    resolvePrimaryAuditHmacKeyFromEnv(envSample),
    'prod-auth-audit-key-with-at-least-32-chars-0001',
  );

  // AUDIT_INTEGRITY_KEY priority preserved when set
  const withPrimary = {
    ...envSample,
    AUDIT_INTEGRITY_KEY: 'prod-primary-integrity-key-at-least-32-chars-9999',
  };
  assert.equal(
    resolvePrimaryAuditHmacKey(makeMinimalConfig(withPrimary)),
    'prod-primary-integrity-key-at-least-32-chars-9999',
  );

  // BUG-066: deterministic dev/test key & production fail-fast
  const keyA = resolveExportAtRestKey({ NODE_ENV: 'development' });
  const keyB = resolveExportAtRestKey({ NODE_ENV: 'test' });
  assert.deepEqual(keyA, keyB);
  assert.throws(() => resolveExportAtRestKey({ NODE_ENV: 'production' }));
  assert.throws(() => resolveExportAtRestKey({ NODE_ENV: 'staging' }));

  const enc = encryptExportArtifactBuffer('job-066', Buffer.from('audit-csv-data'));
  const dec = decryptAndVerifyExportArtifactBuffer('job-066', enc, undefined, true);
  assert.equal(dec?.toString('utf8'), 'audit-csv-data');
});

test('BUG-069 (API) — SecurityDetectionService enforces advisory lock in $transaction, sets detected_user_id = null on AUDIT_INTEGRITY_COMPROMISED, and rejects false-positive OFF_HOURS_ACCESS', async () => {
  const advisoryLocks = [];
  const createdAlerts = [];
  const mockDb = {
    detectionRuleConfig: { findMany: async () => [] },
    auditLog: {
      findMany: async ({ where }) => {
        if (where?.action?.in?.includes('AUDIT_LOG_TAMPERED')) {
          return [{ id: 10n, actor_user_id: 99n, occurred_at: new Date() }];
        }
        if (where?.action?.in?.includes('DOCUMENT_VIEWED')) {
          // Off-hours log WITH missing rank (undefined) and DENIED outcome -> must NOT alert
          return [
            {
              id: 11n,
              actor_user_id: 5n,
              outcome: 'DENIED',
              document_id: 'doc-1',
              occurred_at: new Date('2026-11-26T18:00:00Z'), // 01:00 ICT
              documents: { classification_history: [{ classification_levels: { rank: 4 } }] },
            },
            {
              id: 12n,
              actor_user_id: 5n,
              outcome: 'SUCCESS',
              document_id: 'doc-2',
              occurred_at: new Date('2026-11-26T18:00:00Z'),
              documents: null,
            },
          ];
        }
        return [];
      },
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: { createMany: async () => ({ count: 1 }) },
    $executeRawUnsafe: async (sql, ...args) => {
      advisoryLocks.push({ sql, args });
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const svc = new SecurityDetectionService(mockDb);
  await svc.runAllDetections(undefined, ['AUDIT_INTEGRITY_COMPROMISED', 'OFF_HOURS_ACCESS']);

  assert.equal(createdAlerts.length, 1);
  assert.equal(createdAlerts[0].alert_type, 'AUDIT_INTEGRITY_COMPROMISED');
  assert.equal(createdAlerts[0].detected_user_id, null);
  assert.ok(advisoryLocks.some((c) => c.sql.includes('pg_advisory_xact_lock')));
});
