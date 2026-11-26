import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import {
  hasWatermarkRecipientIdentity,
  renderWatermarkTemplateText,
} from '../../apps/web/app/admin/watermark-helpers.ts';
import { SYSTEM_ROLE_ALLOWED_CODES } from '../../apps/web/lib/rbac-sod.ts';
import { ROLE_DEFAULT_PERMISSIONS } from '../../apps/web/lib/role-permissions.ts';

describe('BUG-055, BUG-061 & BUG-062 Frontend UI Regression Contracts', () => {
  it('BUG-055: preserves identity prefix & full 48-hex token on SECRET/TOP_SECRET no-QR without truncation and wires inline validation in WatermarkTab + WatermarkPreviewCard', async () => {
    const sampleFullCode = `WM-${'0a0b'.repeat(12)}`;

    assert.equal(hasWatermarkRecipientIdentity('{username} | {shortToken}'), true);
    assert.equal(hasWatermarkRecipientIdentity('{{fullName}} | {watermarkToken}'), true);
    assert.equal(hasWatermarkRecipientIdentity('CONFIDENTIAL | {documentCode}'), false);

    // Missing {username}/{fullName} must prepend identity instead of wiping {watermarkToken}
    const rendered = renderWatermarkTemplateText('TOP SECRET | {documentCode} | {watermarkToken}', {
      username: 'qa.reader',
      fullName: 'Lê Đọc Giả',
      classificationCode: 'TOP_SECRET',
      classificationRank: 4,
      includeQrCode: false,
    });
    assert.ok(rendered.startsWith('Lê Đọc Giả (NV-001248) | '));
    assert.ok(rendered.includes(sampleFullCode));

    // Long text > 1000 chars on rank >= 3 with QR disabled must never truncate 48-hex token
    const longRendered = renderWatermarkTemplateText(`${'X'.repeat(1100)} | {username}`, {
      username: 'qa.reader',
      fullName: 'Lê Đọc Giả',
      classificationCode: 'TOP_SECRET',
      classificationRank: 4,
      includeQrCode: false,
    });
    assert.ok(longRendered.length <= 1000);
    assert.ok(longRendered.endsWith(sampleFullCode));

    const [tabSrc, previewSrc, hookSrc] = await Promise.all([
      readFile(new URL('../../apps/web/app/admin/tabs/watermark-tab.tsx', import.meta.url), 'utf8'),
      readFile(
        new URL('../../apps/web/app/admin/tabs/watermark-preview-card.tsx', import.meta.url),
        'utf8',
      ),
      readFile(
        new URL('../../apps/web/app/admin/hooks/use-watermark-settings.ts', import.meta.url),
        'utf8',
      ),
    ]);
    assert.match(tabSrc, /hasWatermarkRecipientIdentity/u);
    assert.match(tabSrc, /classificationCode=\{activeConfig\?\.classificationLevel\?\.code\}/u);
    assert.match(tabSrc, /classificationRank=\{activeConfig\?\.classificationLevel\?\.rank\}/u);
    assert.match(previewSrc, /includeQrCode:\s*showQr/u);
    assert.match(hookSrc, /hasWatermarkRecipientIdentity/u);
  });

  it('BUG-061: IncidentAnalysisForm & IncidentDetailModal require at least one recipient and remove misleading "(tùy chọn)" labels', async () => {
    const [formSrc, modalSrc] = await Promise.all([
      readFile(
        new URL('../../apps/web/app/security/modals/incident-analysis-form.tsx', import.meta.url),
        'utf8',
      ),
      readFile(
        new URL('../../apps/web/app/security/modals/incident-detail-modal.tsx', import.meta.url),
        'utf8',
      ),
    ]);
    assert.doesNotMatch(formSrc, /\(tùy chọn\)/iu);
    assert.match(formSrc, /ít nhất một người nhận/iu);
    assert.match(modalSrc, /!submittedToOwner\.trim\(\)\s*&&\s*!submittedToAdmin\.trim\(\)/u);
  });

  it('BUG-062: grants NOTIFICATION_VIEW across all 5 system roles on FE SoD matrix and enables notification bell for all authenticated users', async () => {
    for (const role of [
      'SYSTEM_ADMIN',
      'SECURITY_OFFICER',
      'AUDITOR',
      'DOCUMENT_OWNER',
      'DOCUMENT_READER',
    ]) {
      assert.equal(
        SYSTEM_ROLE_ALLOWED_CODES[role]?.has('NOTIFICATION_VIEW'),
        true,
        `${role} must include NOTIFICATION_VIEW in SYSTEM_ROLE_ALLOWED_CODES`,
      );
      assert.equal(
        ROLE_DEFAULT_PERMISSIONS[role].includes('NOTIFICATION:VIEW'),
        true,
        `${role} must include NOTIFICATION:VIEW in ROLE_DEFAULT_PERMISSIONS`,
      );
    }

    const headerSrc = await readFile(
      new URL('../../apps/web/components/navigation/app-header.tsx', import.meta.url),
      'utf8',
    );
    assert.match(headerSrc, /canViewNotifications\s*=\s*Boolean\(isAuthenticated && user\)/u);
  });
});
