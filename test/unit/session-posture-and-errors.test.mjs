import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  formatSessionRiskFactorLabels,
  localizeApiErrorMessage,
  resolveDocumentAccessPrecheck,
  shouldOfferMfaActionForError,
} from '../../apps/web/lib/api-error-messages.ts';
import { isValidDeviceFingerprint } from '../../apps/web/lib/device-fingerprint.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm Chứng Bản Dịch Lỗi ABAC Chi Tiết, Khuyến Nghị MFA, Tiền Kiểm Phiên & Dấu Vân Tay Thiết Bị
 */
describe('ABAC Detailed Error Localization, MFA Action Detection & Session Posture Precheck', () => {
  it('formats EXPLICIT_DENY with exact riskScore and Vietnamese riskFactors without misleading Top Secret examples', () => {
    const highRiskMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: EXPLICIT_DENY',
      details: {
        reasonCode: 'EXPLICIT_DENY',
        riskScore: 90,
        riskFactors: [
          'UNTRUSTED_NETWORK',
          'NO_MFA',
          'SENSITIVE_NO_MFA',
          'UNTRUSTED_DEVICE',
          'OFF_HOURS_ACCESS',
          'ACTIVE_HIGH_SECURITY_ALERT',
        ],
      },
    });
    assert.match(highRiskMsg, /90\/100/);
    assert.match(highRiskMsg, /mạng ngoài dải tin cậy/);
    assert.match(highRiskMsg, /chưa xác thực đa yếu tố \(MFA\)/);
    assert.match(highRiskMsg, /ngoài khung giờ hành chính/);
    assert.match(highRiskMsg, /cảnh báo an ninh mức Cao/);
    assert.doesNotMatch(highRiskMsg, /ví dụ: tài liệu Tuyệt mật/i);

    // Deduplicates SENSITIVE_NO_MFA when NO_MFA is already present
    const labels = formatSessionRiskFactorLabels([
      'NO_MFA',
      'SENSITIVE_NO_MFA',
      'UNTRUSTED_DEVICE',
    ]);
    assert.equal(labels.length, 2);

    // Low-risk EXPLICIT_DENY (e.g. department isolation or time rule) must NOT blame Top Secret MFA or high risk
    const deptRuleMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: EXPLICIT_DENY',
      details: {
        reasonCode: 'EXPLICIT_DENY',
        riskScore: 15,
        riskFactors: ['UNTRUSTED_DEVICE'],
      },
    });
    assert.match(deptRuleMsg, /quy tắc chặn theo phạm vi phòng ban/i);
    assert.doesNotMatch(deptRuleMsg, /Tuyệt mật/i);

    // Low-risk EXPLICIT_DENY on untrusted network mentions untrusted network context
    const untrustedNetMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: EXPLICIT_DENY',
      details: {
        reasonCode: 'EXPLICIT_DENY',
        riskScore: 45,
        riskFactors: ['UNTRUSTED_NETWORK', 'UNTRUSTED_DEVICE'],
      },
    });
    assert.match(untrustedNetMsg, /mạng ngoài dải tin cậy/);
  });

  it('offers MFA shortcut for both STEP_UP_MFA_REQUIRED and POLICY_DENIED with NO_MFA/SENSITIVE_NO_MFA factors', () => {
    assert.equal(shouldOfferMfaActionForError('STEP_UP_MFA_REQUIRED'), true);
    assert.equal(
      shouldOfferMfaActionForError('POLICY_DENIED', {
        reasonCode: 'EXPLICIT_DENY',
        riskScore: 85,
        riskFactors: ['UNTRUSTED_NETWORK', 'NO_MFA'],
      }),
      true,
    );
    assert.equal(
      shouldOfferMfaActionForError('POLICY_DENIED', {
        reasonCode: 'EXPLICIT_DENY',
        riskScore: 85,
        riskFactors: ['UNTRUSTED_NETWORK', 'ACTIVE_CRITICAL_SECURITY_ALERT'],
      }),
      false,
    );
    assert.equal(shouldOfferMfaActionForError('DOCUMENT_ACCESS_DENIED'), false);
  });

  it('evaluates pre-click document access posture accurately across clearance ranks and risk levels', () => {
    assert.deepEqual(resolveDocumentAccessPrecheck(null, 4), {
      blocked: false,
      requiresMfa: false,
      reason: null,
    });

    const basePosture = {
      mfaVerified: false,
      mfaEnabled: true,
      trustedNetwork: true,
      deviceTrust: true,
      riskScore: 15,
      sensitiveRiskScore: 25,
      riskThreshold: 80,
      highRiskBlocked: false,
      sensitiveHighRiskBlocked: false,
      topSecretRequiresMfa: true,
      riskFactors: ['NO_MFA'],
      evaluatedAt: '2026-11-26T00:00:00.000Z',
    };

    // Rank 1..3 permitted when risk < 80, Rank 4 (TOP_SECRET) blocked requiring MFA
    assert.equal(resolveDocumentAccessPrecheck(basePosture, 2).blocked, false);
    assert.equal(resolveDocumentAccessPrecheck(basePosture, 3).blocked, false);
    const tsPrecheck = resolveDocumentAccessPrecheck(basePosture, 4);
    assert.equal(tsPrecheck.blocked, true);
    assert.equal(tsPrecheck.requiresMfa, true);
    assert.match(tsPrecheck.reason ?? '', /Tuyệt mật.*MFA/i);

    // Sensitive-only high risk (score 75 for rank 1..2, 85 for rank 3..4)
    const sensitiveRiskPosture = {
      ...basePosture,
      riskScore: 75,
      sensitiveRiskScore: 85,
      sensitiveHighRiskBlocked: true,
      riskFactors: [
        'UNTRUSTED_NETWORK',
        'NO_MFA',
        'OFF_HOURS_ACCESS',
        'ACTIVE_HIGH_SECURITY_ALERT',
      ],
    };
    assert.equal(resolveDocumentAccessPrecheck(sensitiveRiskPosture, 2).blocked, false);
    const secretRisk = resolveDocumentAccessPrecheck(sensitiveRiskPosture, 3);
    assert.equal(secretRisk.blocked, true);
    assert.equal(secretRisk.requiresMfa, true);
    assert.match(secretRisk.reason ?? '', /85\/80/);

    // Global high risk with MFA already verified -> blocked without misleading MFA CTA
    const mfaVerifiedHighRisk = {
      ...basePosture,
      mfaVerified: true,
      topSecretRequiresMfa: false,
      riskScore: 85,
      sensitiveRiskScore: 85,
      highRiskBlocked: true,
      sensitiveHighRiskBlocked: true,
      riskFactors: ['UNTRUSTED_NETWORK', 'ACTIVE_CRITICAL_SECURITY_ALERT'],
    };
    const blockedNoMfaCta = resolveDocumentAccessPrecheck(mfaVerifiedHighRisk, 1);
    assert.equal(blockedNoMfaCta.blocked, true);
    assert.equal(blockedNoMfaCta.requiresMfa, false);
  });

  it('validates stable deviceFingerprint format and verifies reader & owner delivery integration', () => {
    assert.equal(isValidDeviceFingerprint('dfp-0123456789abcdef0123456789abcdef'), true);
    assert.equal(isValidDeviceFingerprint('short'), false);
    assert.equal(isValidDeviceFingerprint('dfp-invalid!chars'), false);
    assert.equal(isValidDeviceFingerprint(null), false);

    const readerViewer = fs.readFileSync(
      path.join(webRoot, 'app/reader/hooks/use-reader-viewer.ts'),
      'utf8',
    );
    const ownerDelivery = fs.readFileSync(
      path.join(webRoot, 'app/owner/hooks/use-owner-delivery.ts'),
      'utf8',
    );
    const readerWorkspace = fs.readFileSync(
      path.join(webRoot, 'app/reader/reader-workspace.tsx'),
      'utf8',
    );
    const ownerWorkspace = fs.readFileSync(
      path.join(webRoot, 'app/owner/owner-workspace.tsx'),
      'utf8',
    );

    assert.match(readerViewer, /getOrCreateDeviceFingerprint/);
    assert.match(readerViewer, /shouldOfferMfaActionForError/);
    assert.match(ownerDelivery, /getOrCreateDeviceFingerprint/);
    assert.match(ownerDelivery, /shouldOfferMfaActionForError/);
    assert.match(ownerDelivery, /mfaActionRequired/);
    assert.match(readerWorkspace, /SessionPostureBanner/);
    assert.match(ownerWorkspace, /SessionPostureBanner/);
    assert.match(ownerWorkspace, /delivery\.mfaActionRequired/);
  });
});
