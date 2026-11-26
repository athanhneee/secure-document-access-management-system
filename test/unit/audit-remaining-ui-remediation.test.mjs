/**
 * Suite Kiểm Thử Hồi Quy Frontend & ABAC Local Simulator Cho Báo Cáo Kiểm Toán Còn Lại (`HIGH-16`..`HIGH-21`, `MED-18`..`MED-28`, `LOW-3`, `LOW-13`, `LOW-14`)
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Cho phép Node 24 native TS loader phân giải import nội bộ không có hậu tố `.ts` của Next.js
registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (error) {
      if (specifier.startsWith('./') || specifier.startsWith('../')) {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw error;
    }
  },
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const webRoot = path.join(repoRoot, 'apps/web');

function readWeb(relPath) {
  return fs.readFileSync(path.join(webRoot, relPath), 'utf8');
}

function collectWebSourceFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name.startsWith('.next') || entry.name === 'node_modules') continue;
      results.push(...collectWebSourceFiles(full));
    } else if (/\.(ts|tsx)$/u.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

describe('Audit Remaining UI Remediation (HIGH-16..21, MED-18..28)', () => {
  it('[HIGH-16 / BUG-030] wires Edit Metadata, Transfer Owner, and manual Set Current Version UI in Owner portal', () => {
    const editModal = readWeb('app/owner/modals/edit-document-modal.tsx');
    const transferModal = readWeb('app/owner/modals/transfer-owner-modal.tsx');
    const versionModal = readWeb('app/owner/modals/version-history-modal.tsx');
    const lifecycleHook = readWeb('app/owner/hooks/use-document-lifecycle.ts');
    const docsTab = readWeb('app/owner/tabs/documents-tab.tsx');

    assert.match(editModal, /noValidate/);
    assert.match(editModal, /showClose=\{!isSaving\}/);
    assert.match(transferModal, /noValidate/);
    assert.match(transferModal, /showClose=\{!isTransferring\}/);
    assert.match(versionModal, /Đặt làm hiện hành/);
    assert.match(versionModal, /Hiện hành/);
    assert.match(versionModal, /break-all/);

    assert.match(lifecycleHook, /method:\s*'PATCH'/);
    assert.match(lifecycleHook, /\/transfer-owner/);
    assert.match(lifecycleHook, /\/current-version/);

    assert.doesNotMatch(docsTab, /canManage:\s*_canManage/);
    assert.match(docsTab, /onOpenEditMetadata/);
    assert.match(docsTab, /onOpenTransferOwner/);
  });

  it('[HIGH-17 & HIGH-18] guards NotificationBell hydration before cache write and sets StrictMode DLP probe flag only after non-aborted settle', () => {
    const bell = readWeb('components/navigation/notification-bell-dialog.tsx');
    const secData = readWeb('app/security/hooks/use-security-data.ts');

    assert.match(bell, /hasHydrated/);
    assert.match(bell, /if \(!hasHydrated\) return;/);

    const effectBlock = secData.slice(
      secData.indexOf('const includeProbe = !didInitialDlpProbeRef.current'),
    );
    assert.doesNotMatch(
      effectBlock.slice(0, 140),
      /didInitialDlpProbeRef\.current\s*=\s*true/,
      'didInitialDlpProbeRef must not be flipped synchronously inside StrictMode effect',
    );
    assert.match(secData, /didInitialDlpProbeRef\.current = true/);
  });

  it('[HIGH-19 & MED-19] aligns RBAC visibility across Owner, Security, Auditor and Upload Wizard', () => {
    const ownerWorkspace = readWeb('app/owner/owner-workspace.tsx');
    const ownerData = readWeb('app/owner/hooks/use-owner-data.ts');
    const uploadWizard = readWeb('app/owner/hooks/use-upload-wizard.ts');
    const securityWorkspace = readWeb('app/security/security-workspace.tsx');
    const auditorWorkspace = readWeb('app/auditor/auditor-workspace.tsx');
    const authContext = readWeb('lib/auth-context.tsx');

    assert.match(ownerData, /const canViewRequests = hasPermission\('ACCESS_REQUEST:DECIDE'\)/);
    assert.match(ownerWorkspace, /const canViewRequests = canDecideRequest/);
    assert.match(uploadWizard, /if \(canCreateVersion\)/);
    assert.match(uploadWizard, /if \(canClassify\)/);

    assert.match(authContext, /hasGlobalPermission/);
    assert.match(securityWorkspace, /isReadOnlyAuditor/);
    assert.match(securityWorkspace, /hasGlobalPermission\('SECURITY_ALERT:MANAGE'\)/);
    assert.match(securityWorkspace, /hasGlobalPermission\('POLICY:SIMULATE'\)/);
    assert.match(auditorWorkspace, /hasGlobalPermission\('SYSTEM_REPORT:EXPORT'\)/);
  });

  it('[HIGH-20] fixes Reader SSE positive document/grant matching and structural 60s grant expiry diffing', () => {
    const readerViewer = readWeb('app/reader/hooks/use-reader-viewer.ts');
    const readerCatalog = readWeb('app/reader/hooks/use-reader-catalog.ts');

    assert.match(
      readerViewer,
      /const matchedDoc = Boolean\(p\?\.documentId && p\.documentId === currentDoc\.documentId\)/,
    );
    assert.match(
      readerViewer,
      /const matchedGrant = Boolean\(p\?\.id && p\.id === currentDoc\.id\)/,
    );
    assert.match(readerViewer, /if \(!matchedDoc && !matchedGrant\)/);

    assert.match(readerCatalog, /status:\s*'ACTIVE'/);
    assert.match(readerCatalog, /buildGrantedDocsSignature/);
    assert.match(readerCatalog, /buildGrantedMapSignature/);
  });

  it('[HIGH-21] enforces zero red borders across apps/web and strict UUID validation in ServerSimulatorPanel', () => {
    const files = [
      ...collectWebSourceFiles(path.join(webRoot, 'app')),
      ...collectWebSourceFiles(path.join(webRoot, 'components')),
    ];
    for (const filePath of files) {
      const content = fs.readFileSync(filePath, 'utf8');
      assert.doesNotMatch(
        content,
        /border-\[#C13515\]/u,
        `${path.relative(webRoot, filePath)} must not use red #C13515 borders`,
      );
    }

    const serverSim = readWeb('components/abac/server-simulator-panel.tsx');
    assert.doesNotMatch(serverSim, /placeholder="1"/);
    assert.match(serverSim, /UUID/i);

    const mfaCard = readWeb('app/mfa/mfa-enrollment-card.tsx');
    assert.match(mfaCard, /recoveryCodes && recoveryCodes\.length > 0/);
  });

  it('[MED-18] enforces canonical IP equality, Gregorian date validation, and HH:MM clock comparison in local ABAC simulator', async () => {
    const { canonicalizeIpAddress } =
      await import('../../apps/web/components/abac/cidr-matcher.ts');
    const { evaluatePolicySetSimulation, parseStrictIsoTimestamp } =
      await import('../../apps/web/components/abac/simulator-evaluator.ts');

    assert.equal(canonicalizeIpAddress('::ffff:10.0.0.5'), canonicalizeIpAddress('10.0.0.5'));
    assert.equal(
      canonicalizeIpAddress('2001:0db8:0000:0000::1'),
      canonicalizeIpAddress('2001:db8::1'),
    );
    assert.equal(canonicalizeIpAddress('not-an-ip'), null);
    assert.equal(parseStrictIsoTimestamp('2026-02-31'), null);
    assert.equal(parseStrictIsoTimestamp('2026-02-28') !== null, true);

    const result = evaluatePolicySetSimulation(
      [
        {
          id: 'rule-ip-clock',
          code: 'POL-TEST-PARITY',
          name: 'Parity check',
          effect: 'PERMIT',
          priority: 10,
          targetResource: 'DOCUMENT',
          targetAction: 'VIEW',
          combiningAlgorithm: 'DENY_OVERRIDES',
          isActive: true,
          obligations: [],
          groups: [
            {
              id: 1,
              conditions: [
                { id: 'c1', attribute: 'environment.ip', operator: 'EQ', expected: '10.0.0.5' },
                {
                  id: 'c2',
                  attribute: 'environment.currentTime',
                  operator: 'GTE',
                  expected: '2026-01-01T00:00:00Z',
                },
                {
                  id: 'c3',
                  attribute: 'environment.currentTime',
                  operator: 'TIME_BETWEEN',
                  expected: { start: '08:00', end: '18:00', timeZone: 'Asia/Ho_Chi_Minh' },
                },
              ],
            },
          ],
        },
      ],
      'VIEW',
      {
        clearanceRank: 2,
        departmentId: '1',
        employmentStatus: 'ACTIVE_STAFF',
        projects: [],
      },
      {
        classificationRank: 2,
        departmentId: '1',
        category: 'FINANCE',
        status: 'ACTIVE',
        ownerId: '2',
      },
      {
        currentTime: '10:30',
        ip: '::ffff:10.0.0.5',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: 0,
      },
    );

    assert.equal(result.decision, 'PERMIT');
  });
});
