/**
 * @module AbacRiskAndMfaTests
 * Thuật toán: Bộ Kiểm Thử Đơn Vị Cho Chấm Điểm Rủi Ro Phiên Thời Gian Thực, Step-Up MFA Trên Luật DENY
 * (`POL-DENY-TOP-SECRET-WITHOUT-MFA` áp dụng `ALL`), Và Đồng Bộ Dữ Liệu Hạt Giống ABAC.
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import {
  computeSessionRiskScore,
  evaluatePepSessionRisk,
} from '../dist/modules/abac/session-risk-scorer.helper.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { createActivePepDocumentRow } from './helpers/document-delivery-mocks.mjs';

const BASELINE_COMPILED_POLICY = {
  version: '100',
  requiredAttributes: ['subject.clearanceRank', 'resource.classificationRank'],
  rules: [
    {
      id: '1',
      code: 'POL-DENY-HIGH-RISK-SESSION',
      effect: 'DENY',
      priority: 10,
      targetResource: 'DOCUMENT',
      targetAction: null,
      combiningAlgorithm: 'DENY_OVERRIDES',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: null,
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'c1',
              attribute: 'environment.riskScore',
              operator: 'GTE',
              expected: 80,
            },
          ],
        },
      ],
      obligations: [{ type: 'NO_CACHE' }],
    },
    {
      id: '2',
      code: 'POL-DENY-TOP-SECRET-WITHOUT-MFA',
      effect: 'DENY',
      priority: 20,
      targetResource: 'DOCUMENT',
      targetAction: null,
      combiningAlgorithm: 'DENY_OVERRIDES',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: null,
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'c2',
              attribute: 'resource.classificationRank',
              operator: 'GTE',
              expected: 4,
            },
            {
              id: 'c3',
              attribute: 'environment.mfa',
              operator: 'EQ',
              expected: false,
            },
          ],
        },
      ],
      obligations: [{ type: 'REQUIRE_MFA' }],
    },
    {
      id: '3',
      code: 'POL-PERMIT-CLEARED-ACTIVE-STAFF',
      effect: 'PERMIT',
      priority: 100,
      targetResource: 'DOCUMENT',
      targetAction: null,
      combiningAlgorithm: 'DENY_OVERRIDES',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: null,
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'c4',
              attribute: 'subject.employmentStatus',
              operator: 'IN',
              expected: ['ACTIVE', 'ACTIVE_STAFF'],
            },
            {
              id: 'c5',
              attribute: 'resource.status',
              operator: 'EQ',
              expected: 'ACTIVE',
            },
          ],
        },
      ],
      obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }],
    },
  ],
};

// 10:00 ICT (Asia/Ho_Chi_Minh = UTC+7) -> business hours
const BUSINESS_HOURS_DATE = new Date('2026-06-15T03:00:00.000Z');
// 23:30 ICT -> off hours
const OFF_HOURS_DATE = new Date('2026-06-15T16:30:00.000Z');

test('computeSessionRiskScore: trusted intranet MFA session scores 0, anomalous external session hits >= 80', () => {
  const clean = computeSessionRiskScore({
    trustedNetwork: true,
    mfa: true,
    deviceTrust: true,
    ipChangedFromAuthSession: false,
    userAgentChangedFromAuthSession: false,
    failedLoginCount: 0,
    openHighAlertCount: 0,
    openCriticalAlertCount: 0,
    classificationRank: 4,
    now: BUSINESS_HOURS_DATE,
  });
  assert.equal(clean.riskScore, 0);
  assert.deepEqual(clean.factors, []);

  // Trusted intranet without MFA on TOP_SECRET stays < 80 so Law 2 (Step-Up MFA) triggers instead of Law 1
  const noMfaIntranet = computeSessionRiskScore({
    trustedNetwork: true,
    mfa: false,
    deviceTrust: false,
    ipChangedFromAuthSession: false,
    userAgentChangedFromAuthSession: false,
    failedLoginCount: 0,
    openHighAlertCount: 0,
    openCriticalAlertCount: 0,
    classificationRank: 4,
    now: BUSINESS_HOURS_DATE,
  });
  assert.equal(noMfaIntranet.riskScore, 40);
  assert.ok(noMfaIntranet.riskScore < 80);

  // External untrusted network + IP drift + untrusted device + off-hours + no MFA -> clamped 100 >= 80
  const hijackedExternal = computeSessionRiskScore({
    trustedNetwork: false,
    mfa: false,
    deviceTrust: false,
    ipChangedFromAuthSession: true,
    userAgentChangedFromAuthSession: true,
    failedLoginCount: 4,
    openHighAlertCount: 1,
    openCriticalAlertCount: 0,
    classificationRank: 3,
    now: OFF_HOURS_DATE,
  });
  assert.equal(hijackedExternal.riskScore, 100);
  assert.ok(hijackedExternal.factors.includes('UNTRUSTED_NETWORK'));
  assert.ok(hijackedExternal.factors.includes('SESSION_IP_DRIFT'));
  assert.ok(hijackedExternal.factors.includes('ACTIVE_HIGH_SECURITY_ALERT'));

  // Active CRITICAL security alert on external untrusted device hits >= 80 even with MFA
  const criticalAlert = computeSessionRiskScore({
    trustedNetwork: false,
    mfa: true,
    deviceTrust: false,
    ipChangedFromAuthSession: false,
    userAgentChangedFromAuthSession: false,
    failedLoginCount: 0,
    openHighAlertCount: 0,
    openCriticalAlertCount: 1,
    classificationRank: 2,
    now: BUSINESS_HOURS_DATE,
  });
  assert.equal(criticalAlert.riskScore, 85);
  assert.ok(criticalAlert.factors.includes('ACTIVE_CRITICAL_SECURITY_ALERT'));
});

test('evaluatePepSessionRisk collects authSession IP drift, failed logins, SOC alerts and known device fingerprint', async () => {
  const mockDb = {
    authSession: {
      findUnique: async () => ({
        ip_address: '10.10.1.5',
        user_agent: 'CorpBrowser/1.0',
      }),
    },
    user: {
      findUnique: async () => ({ failed_login_count: 5 }),
    },
    securityAlert: {
      findMany: async () => [{ severity: 'HIGH' }],
    },
    accessSession: {
      findFirst: async () => null,
    },
  };

  const assessment = await evaluatePepSessionRisk({
    database: mockDb,
    principal: { userId: 7n, sessionId: 'auth-s-1', username: 'alice', roles: [], mfa: false },
    context: { ip: '203.0.113.55', userAgent: 'UnknownBot/2.0', correlationId: 'corr-1' },
    trustedNetwork: false,
    classificationRank: 3,
    deviceFingerprint: 'unseen-fp-1234',
    now: OFF_HOURS_DATE,
  });

  assert.equal(assessment.deviceTrust, false);
  assert.equal(assessment.riskScore, 100);
  assert.ok(assessment.factors.includes('SESSION_IP_DRIFT'));
  assert.ok(assessment.factors.includes('SESSION_UA_DRIFT'));
  assert.ok(assessment.factors.includes('REPEATED_FAILED_LOGINS'));
  assert.ok(assessment.factors.includes('ACTIVE_HIGH_SECURITY_ALERT'));
});

test('Policy Engine & DocumentPEP: Law 1 blocks high-risk live sessions (riskScore >= 80) while Law 2 returns STEP_UP_MFA_REQUIRED across ALL actions', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  const realAbac = {
    evaluate: async (input) => evaluatePolicy(BASELINE_COMPILED_POLICY, input),
  };
  const config = {
    get: (key) => (key === 'ABAC_TRUSTED_NETWORK_CIDRS' ? '10.0.0.0/8,127.0.0.0/8' : ''),
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAudit = { record: async () => {} };

  // Case 1: High-risk external session with IP drift + CRITICAL alert triggers Law 1 in real PEP runtime!
  const highRiskDb = {
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 2,
          allow_download: true,
          require_watermark: true,
        }),
    },
    user: {
      findUnique: async () => ({ department_id: 1n, status: 'ACTIVE', failed_login_count: 3 }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 4, is_active: true } }),
      findMany: async () => [],
    },
    authSession: {
      findUnique: async () => ({ ip_address: '10.0.0.9', user_agent: 'CorpBrowser' }),
    },
    securityAlert: {
      findMany: async () => [{ severity: 'CRITICAL' }],
    },
    accessSession: {
      findFirst: async () => null,
      create: async ({ data }) => data,
    },
  };
  const highRiskPep = new DocumentPepService(realAbac, mockGrants, mockAudit, highRiskDb, config);

  await assert.rejects(
    async () => {
      await highRiskPep.enforceAccess(
        docId,
        {
          userId: 42n,
          sessionId: 'auth-1',
          username: 'reader',
          roles: ['DOCUMENT_READER'],
          mfa: true,
        },
        { ip: '198.51.100.77', userAgent: 'CorpBrowser', correlationId: 'corr-risk' },
        { action: 'VIEW', grantId, now: BUSINESS_HOURS_DATE },
      );
    },
    (err) => {
      const res = err.getResponse?.();
      return (
        res?.errorCode === AppErrorCode.POLICY_DENIED &&
        res?.details?.reasonCode === 'EXPLICIT_DENY' &&
        res?.details?.riskScore >= 80
      );
    },
  );

  // Case 2: Trusted intranet session WITHOUT MFA on TOP_SECRET (rank 4) -> Law 2 triggers STEP_UP_MFA_REQUIRED on VIEW AND DOWNLOAD!
  const topSecretDb = {
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 4,
          allow_download: true,
          require_watermark: true,
        }),
    },
    user: {
      findUnique: async () => ({ department_id: 1n, status: 'ACTIVE', failed_login_count: 0 }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 4, is_active: true } }),
      findMany: async () => [],
    },
    authSession: {
      findUnique: async () => ({ ip_address: '10.0.0.9', user_agent: 'CorpBrowser' }),
    },
    securityAlert: { findMany: async () => [] },
    accessSession: {
      findFirst: async () => ({ id: 'prior-trusted-session' }),
      create: async ({ data }) => data,
    },
  };
  const topSecretPep = new DocumentPepService(realAbac, mockGrants, mockAudit, topSecretDb, config);

  for (const action of ['VIEW', 'DOWNLOAD']) {
    await assert.rejects(
      async () => {
        await topSecretPep.enforceAccess(
          docId,
          {
            userId: 42n,
            sessionId: 'auth-2',
            username: 'reader',
            roles: ['DOCUMENT_READER'],
            mfa: false,
          },
          { ip: '10.0.0.9', userAgent: 'CorpBrowser', correlationId: `corr-mfa-${action}` },
          { action, grantId, deviceFingerprint: 'trusted-device-fp', now: BUSINESS_HOURS_DATE },
        );
      },
      (err) => {
        const res = err.getResponse?.();
        return (
          res?.errorCode === AppErrorCode.STEP_UP_MFA_REQUIRED &&
          res?.details?.reasonCode === 'STEP_UP_MFA_REQUIRED'
        );
      },
    );
  }

  // Case 3: Trusted intranet session WITH MFA on TOP_SECRET -> PERMIT with obligations
  const permitResult = await topSecretPep.enforceAccess(
    docId,
    { userId: 42n, sessionId: 'auth-2', username: 'reader', roles: ['DOCUMENT_READER'], mfa: true },
    { ip: '10.0.0.9', userAgent: 'CorpBrowser', correlationId: 'corr-permit' },
    { action: 'VIEW', grantId, deviceFingerprint: 'trusted-device-fp', now: BUSINESS_HOURS_DATE },
  );
  assert.ok(permitResult.sessionId);
  assert.equal(permitResult.watermarkRequired, true);
  assert.ok(permitResult.obligations.includes('REQUIRE_WATERMARK'));
  assert.ok(permitResult.obligations.includes('NO_CACHE'));

  // Case 4: Combined Law 1 (riskScore >= 80) + Law 2 (TOP_SECRET & !mfa) MUST remain EXPLICIT_DENY (not downgraded to STEP_UP_MFA_REQUIRED)
  const combinedResult = evaluatePolicy(BASELINE_COMPILED_POLICY, {
    resourceType: 'DOCUMENT',
    action: 'SHARE',
    subject: {
      clearanceRank: 4,
      departmentId: '1',
      employmentStatus: 'ACTIVE',
      projects: [],
    },
    resource: {
      classificationRank: 4,
      ownerId: '1',
      departmentId: '1',
      category: 'SECURITY_OPERATIONS',
      status: 'ACTIVE',
    },
    environment: {
      currentTime: BUSINESS_HOURS_DATE.toISOString(),
      ip: '203.0.113.10',
      trustedNetwork: false,
      deviceTrust: false,
      mfa: false,
      riskScore: 90,
    },
  });
  assert.equal(combinedResult.decision, 'DENY');
  assert.equal(combinedResult.reasonCode, 'EXPLICIT_DENY');
  assert.deepEqual(combinedResult.matchedRuleIds, ['1', '2', '3']);
  assert.deepEqual(combinedResult.obligations, []);
});

test('Seed catalog and Supabase SQL align POL-DENY-TOP-SECRET-WITHOUT-MFA to ALL (null) and object obligations', () => {
  const seedCatalogSource = readFileSync(
    new URL('../../../packages/database/prisma/seed-catalog.ts', import.meta.url),
    'utf8',
  );
  const supabaseSqlSource = readFileSync(
    new URL('../../../supabase/01_supabase_full_schema_and_seed.sql', import.meta.url),
    'utf8',
  );

  // Law 2 in seed-catalog.ts must have target_action: null and object obligations
  const law2Start = seedCatalogSource.indexOf("code: 'POL-DENY-TOP-SECRET-WITHOUT-MFA'");
  const law3Start = seedCatalogSource.indexOf("code: 'POL-PERMIT-CLEARED-ACTIVE-STAFF'");
  assert.ok(law2Start > 0 && law3Start > law2Start);
  const law2Block = seedCatalogSource.slice(law2Start, law3Start);
  assert.match(law2Block, /target_action:\s*null/u);
  assert.match(law2Block, /obligations:\s*\[\{\s*type:\s*'REQUIRE_MFA'\s*\}\]/u);

  // All 3 baseline policies in seed-catalog.ts must use object obligations
  assert.doesNotMatch(seedCatalogSource, /obligations:\s*\['NO_CACHE'\]/u);
  assert.doesNotMatch(seedCatalogSource, /obligations:\s*\['REQUIRE_WATERMARK'/u);

  // Supabase SQL must also update target_action on conflict and use JSON object arrays
  assert.match(supabaseSqlSource, /'\[\{"type":"REQUIRE_MFA"\}\]'::jsonb/u);
  assert.match(supabaseSqlSource, /'\[\{"type":"NO_CACHE"\}\]'::jsonb/u);
  assert.match(supabaseSqlSource, /target_action\s*=\s*EXCLUDED\.target_action/u);
});
