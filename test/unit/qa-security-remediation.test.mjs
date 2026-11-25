import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  filterNetworkDlpAlerts,
  filterSecurityAlerts,
  mapAlertDto,
  mapIncidentDto,
  mapWatermarkVerifyDto,
  normalizeWatermarkTokenInput,
} from '../../apps/web/app/security/helpers.ts';
import {
  formatAuditActionLabel,
  formatClassificationLabel,
  formatDetectionRuleLabel,
} from '../../apps/web/lib/ui-labels.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Bộ Kiểm Thử Hồi Quy Giao Diện, DTO & Bảo Mật Biên Cho Vai Trò `qa.security` (`SECURITY_OFFICER`)
 * Mục đích: Xác minh toàn bộ sửa lỗi Batch 1–5 trên lớp Frontend (`helpers.ts`, `ui-labels.ts`, `proxy.ts`, `/mfa`, `/security` 8 tab & hộp thoại)
 *   không thoái lui các bất biến RBAC/SoD, chống giả mạo header IP, chuẩn hóa QR JSON watermark, tách `closingNote`, và `Promise.allSettled`.
 */
describe('qa.security Remediation — Watermark QR JSON, Hex 12–64 & 8 Forensic Fields (N14, #47, #21, #41)', () => {
  it('extracts WM token from raw QR JSON payload, inline text, bare 12–64 hex, and rejects malformed/path traversal inputs', () => {
    const token48 = 'a'.repeat(48);
    const token64 = 'b'.repeat(64);
    const token12 = 'deadbeef1234';

    const fromQrJson = normalizeWatermarkTokenInput(
      JSON.stringify({ token: `WM-${token48}`, u: 'qa.reader', ts: '2026-11-25T08:00:00Z' }),
    );
    assert.deepEqual(fromQrJson, { valid: true, token: `WM-${token48}` });

    const fromPrefix12 = normalizeWatermarkTokenInput(`WM-${token12.toUpperCase()}`);
    assert.deepEqual(fromPrefix12, { valid: true, token: `WM-${token12}` });

    const fromBare64 = normalizeWatermarkTokenInput(token64.toUpperCase());
    assert.deepEqual(fromBare64, { valid: true, token: `WM-${token64}` });

    const fromPdfLine = normalizeWatermarkTokenInput(`Tài liệu mật · ID: WM-${token12} · Nội bộ`);
    assert.deepEqual(fromPdfLine, { valid: true, token: `WM-${token12}` });

    assert.equal(normalizeWatermarkTokenInput('').valid, false);
    assert.equal(normalizeWatermarkTokenInput('WM-12345').valid, false);
    assert.equal(normalizeWatermarkTokenInput('../../etc/passwd').valid, false);
    assert.equal(normalizeWatermarkTokenInput(`WM-${'f'.repeat(65)}`).valid, false);
  });

  it('preserves all 8 forensic provenance fields and Vietnamese classification labels in mapWatermarkVerifyDto', () => {
    const mapped = mapWatermarkVerifyDto({
      verified: true,
      watermarkToken: `WM-${'c'.repeat(48)}`,
      renderedText: 'CONFIDENTIAL | qa.reader | WM-cccccccccccc',
      outputSha256Hash: '1'.repeat(64),
      generatedAt: '2026-11-25T08:30:00.000Z',
      document: {
        title: 'Chiến lược An ninh 2026',
        documentCode: 'DOC-SEC-2026',
        versionNo: 3,
        classificationName: 'TOP_SECRET',
        originalSha256Hash: '2'.repeat(64),
      },
      user: {
        fullName: 'Nguyễn Độc Giả',
        username: 'qa.reader',
        email: 'qa.reader@sda.local',
        employeeCode: 'EMP-9901',
      },
      session: {
        id: 'sess-uuid-01',
        ipAddress: '10.10.20.30',
        userAgent: 'Mozilla/5.0 Chrome/130',
      },
      config: {
        name: 'Watermark Tuyệt Mật',
        opacityPercent: 30,
        includeQrCode: true,
      },
    });

    assert.equal(mapped.verified, true);
    assert.equal(mapped.outputSha256Hash, '1'.repeat(64));
    assert.equal(mapped.originalSha256Hash, '2'.repeat(64));
    assert.equal(mapped.renderedText, 'CONFIDENTIAL | qa.reader | WM-cccccccccccc');
    assert.equal(mapped.recipientEmail, 'qa.reader@sda.local');
    assert.equal(mapped.userAgent, 'Mozilla/5.0 Chrome/130');
    assert.equal(mapped.versionNo, 3);
    assert.equal(mapped.classificationName, 'Tuyệt mật');
    assert.match(mapped.configSummary, /Watermark Tuyệt Mật/u);
    assert.match(mapped.configSummary, /30%/u);
    assert.match(mapped.configSummary, /có mã QR/u);
  });
});

describe('qa.security Remediation — Alert/Incident DTO Mapping & Labels (#01-#03, #11, #19)', () => {
  it('maps alert description, ipAddress, structured notes[], and incident closingNote cleanly', () => {
    const alert = mapAlertDto({
      id: 'alert-uuid-1',
      alertType: 'NETWORK_DLP_VIOLATION',
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
      title: 'Phát hiện rò rỉ dữ liệu mạng',
      description: '[Network DLP] [BLOCKED] Phát hiện từ khóa mật',
      ipAddress: '10.20.30.40',
      detectedAt: '2026-11-25T08:00:00Z',
      notes: [
        {
          id: 'alert-uuid-1-note-0',
          authorName: 'qa.security',
          note: 'Đã cô lập phiên đọc',
          createdAt: '2026-11-25T08:05:00Z',
        },
      ],
    });

    assert.equal(alert.ipAddress, '10.20.30.40');
    assert.equal(alert.description, '[Network DLP] [BLOCKED] Phát hiện từ khóa mật');
    assert.equal(alert.notes.length, 1);
    assert.equal(alert.notes[0]?.note, 'Đã cô lập phiên đọc');
    assert.equal(filterNetworkDlpAlerts([alert]).length, 1);
    assert.equal(filterSecurityAlerts([alert], 'CRITICAL', 'INVESTIGATING').length, 1);

    const inc = mapIncidentDto({
      id: 'inc-1',
      incidentCode: 'INC-2026-001',
      title: 'Sự cố rò rỉ thử nghiệm',
      summary: 'Tóm tắt gốc',
      closingNote: 'Đã xử lý xong toàn bộ',
      status: 'CLOSED',
      createdAt: '2026-11-25T08:00:00Z',
    });
    assert.equal(inc.summary, 'Tóm tắt gốc');
    assert.equal(inc.closingNote, 'Đã xử lý xong toàn bộ');
  });

  it('localizes all 9 real backend/worker alert types, classification levels, and live audit actions without obsolete junk codes', () => {
    const realRuleCodes = [
      'MASS_DOWNLOAD',
      'REPEATED_DENIED',
      'OFF_HOURS_ACCESS',
      'UNTRUSTED_CONTEXT',
      'RETENTION_OVERDUE',
      'AUDIT_INTEGRITY_COMPROMISED',
      'NETWORK_DLP_VIOLATION',
      'REFRESH_TOKEN_REUSE',
      'WEBAUTHN_CLONE_DETECTED',
    ];
    for (const code of realRuleCodes) {
      const label = formatDetectionRuleLabel(code);
      assert.notEqual(label, code, `Rule ${code} must have Vietnamese label`);
      assert.ok(label.length >= 6);
    }

    assert.equal(formatClassificationLabel('TOP_SECRET'), 'Tuyệt mật');
    assert.equal(formatClassificationLabel('CONFIDENTIAL'), 'Mật');
    assert.equal(formatAuditActionLabel('DOCUMENT_VIEWED'), 'Xem tài liệu');
    assert.equal(
      formatAuditActionLabel('INCIDENT_REPORT_IN_REVIEW'),
      'Chuyển thẩm định hồ sơ sự cố',
    );
    assert.equal(formatAuditActionLabel('WATERMARK_VERIFIED'), 'Đối soát truy vết watermark');
  });
});

describe('qa.security Remediation — Static Security, Proxy Anti-Spoofing, MFA Gate & 8-Tab Workspace Contracts', () => {
  it('strips forged X-Forwarded-For / CF-Connecting-IP / X-Real-IP headers in apps/web/proxy.ts unless TRUSTED_EDGE_PROXY=true (N02)', () => {
    const proxySrc = fs.readFileSync(path.join(webRoot, 'proxy.ts'), 'utf8');
    assert.match(proxySrc, /export function buildApiProxyHeaders/u);
    assert.match(proxySrc, /TRUSTED_EDGE_PROXY/u);
    assert.match(proxySrc, /upstreamHeaders\.delete\('x-forwarded-for'\)/u);
    assert.match(proxySrc, /upstreamHeaders\.delete\('cf-connecting-ip'\)/u);
    assert.match(proxySrc, /upstreamHeaders\.delete\('x-real-ip'\)/u);
    assert.match(proxySrc, /upstreamHeaders\.delete\('forwarded'\)/u);
  });

  it('hides first-time MFA enrollment option when already enrolled to prevent 403 MFA_ENROLLMENT_BLOCKED (#27)', () => {
    const loginSrc = fs.readFileSync(path.join(webRoot, 'app/login/page.tsx'), 'utf8');
    const mfaPageSrc = fs.readFileSync(path.join(webRoot, 'app/mfa/page.tsx'), 'utf8');
    assert.match(loginSrc, /enroll=0/u);
    assert.match(mfaPageSrc, /canShowFirstTimeEnroll/u);
    assert.match(mfaPageSrc, /mfaEnrollBlocked/u);
  });

  it('wires Promise.allSettled error isolation, real /dlp-status, 4 SSE channels, no windowMinutes: 60, and 8 permission-gated tabs in /security', () => {
    const hookSrc = fs.readFileSync(
      path.join(webRoot, 'app/security/hooks/use-security-data.ts'),
      'utf8',
    );
    const workspaceSrc = fs.readFileSync(
      path.join(webRoot, 'app/security/security-workspace.tsx'),
      'utf8',
    );
    const incModalSrc = fs.readFileSync(
      path.join(webRoot, 'app/security/modals/create-incident-modal.tsx'),
      'utf8',
    );
    const ruleModalSrc = fs.readFileSync(
      path.join(webRoot, 'app/security/modals/edit-detection-rule-modal.tsx'),
      'utf8',
    );

    assert.match(hookSrc, /Promise\.allSettled/u);
    assert.match(hookSrc, /\/security-operations\/dlp-status/u);
    assert.match(hookSrc, /INCIDENT_REPORT_UPDATED/u);
    assert.match(hookSrc, /DETECTION_RULE_UPDATED/u);
    const hookCodeWithoutComments = hookSrc
      .replace(/\/\/.*$/gmu, '')
      .replace(/\/\*[\s\S]*?\*\//gu, '');
    assert.doesNotMatch(
      hookCodeWithoutComments,
      /windowMinutes:\s*60/u,
      'Must not override per-rule DB window with hardcoded 60',
    );

    assert.match(workspaceSrc, /AuditIntegrityTab/u);
    assert.match(workspaceSrc, /PolicySimulatorTab/u);
    assert.match(workspaceSrc, /<AuthGuard requiredPortal="SECURITY_OFFICER"/u);
    assert.match(workspaceSrc, /=\s*useSecurityData\(\)/u);

    assert.match(incModalSrc, /noValidate/u);
    assert.match(ruleModalSrc, /noValidate/u);
  });
});
