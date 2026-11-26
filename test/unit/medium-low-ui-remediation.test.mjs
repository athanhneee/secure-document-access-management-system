import assert from 'node:assert/strict';
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@/')) {
      for (const ext of ['.ts', '.tsx']) {
        const target = path.join(webRoot, `${specifier.slice(2)}${ext}`);
        if (fs.existsSync(target)) {
          return { url: pathToFileURL(target).href, shortCircuit: true };
        }
      }
    }
    if (
      (specifier.startsWith('./') || specifier.startsWith('../')) &&
      !/\.[a-z0-9]+$/i.test(specifier) &&
      context.parentURL?.startsWith('file:')
    ) {
      const parentDir = path.dirname(fileURLToPath(context.parentURL));
      for (const ext of ['.ts', '.tsx']) {
        const target = path.resolve(parentDir, `${specifier}${ext}`);
        if (fs.existsSync(target)) {
          return { url: pathToFileURL(target).href, shortCircuit: true };
        }
      }
    }
    return nextResolve(specifier, context);
  },
});

const { AUDIT_PARTITIONS, isValidPositiveBigIntId, normalizeWatermarkTokenInput } =
  await import('../../apps/web/app/security/helpers.ts');
const { normalizeAuditorWatermarkInput } =
  await import('../../apps/web/app/auditor/forensics-helpers.ts');
const { AUDIT_PARTITION_OPTIONS } = await import('../../apps/web/app/auditor/helpers.ts');
const {
  applyOptimisticMarkAllRead,
  applyOptimisticMarkRead,
  rollbackOptimisticMarkAllRead,
  rollbackOptimisticMarkRead,
} = await import('../../apps/web/components/navigation/notification-bell-state.ts');
const { getActiveBodyScrollLocks, lockBodyScroll } =
  await import('../../apps/web/components/ui/body-scroll-lock.ts');
const { CLEARANCE_OPTIONS, COMPATIBLE_OPERATORS_BY_TYPE } =
  await import('../../apps/web/components/abac/abac-presets.ts');
const { CLIENT_PAST_TOLERANCE_MS } = await import('../../apps/web/app/admin/helpers.ts');
const { matchesUserActionFilter } = await import('../../apps/web/app/admin/users-query.ts');
const { filterDepartmentsByUploadScope, validateDocumentCodeInput, validateUploadFileInput } =
  await import('../../apps/web/app/owner/upload-validation.ts');
const { mergeActiveReaderGrants } = await import('../../apps/web/app/reader/helpers.ts');

function readWebFile(relPath) {
  return fs.readFileSync(path.join(webRoot, relPath), 'utf8');
}

describe('Groups 5A, 5B & 6 Frontend Remediation Regression Suite (BUG-080 -> BUG-103, BUG-115 -> BUG-120)', () => {
  it('[BUG-080 & BUG-083] shares AUDIT partition across Security/Auditor and normalizes lowercase wm-... tokens cleanly', () => {
    assert.equal(AUDIT_PARTITIONS.includes('AUDIT'), true);
    assert.equal(AUDIT_PARTITION_OPTIONS.includes('AUDIT'), true);

    const lowerInline = normalizeAuditorWatermarkInput('Leak detected: wm-abcdef0123456789 end');
    assert.deepEqual(lowerInline, { valid: true, token: 'WM-abcdef0123456789' });

    const mixedQr = normalizeWatermarkTokenInput('{"token":"wm-001122334455AABB"}');
    assert.deepEqual(mixedQr, { valid: true, token: 'WM-001122334455aabb' });
  });

  it('[BUG-087] validates PositiveBigInt IDs strictly (rejects 0, negatives, and > MAX_PG_BIGINT)', () => {
    assert.equal(isValidPositiveBigIntId('1'), true);
    assert.equal(isValidPositiveBigIntId('9223372036854775807'), true);
    assert.equal(isValidPositiveBigIntId('0'), false);
    assert.equal(isValidPositiveBigIntId('-1'), false);
    assert.equal(isValidPositiveBigIntId('9223372036854775808'), false);
    assert.equal(isValidPositiveBigIntId('001'), false);
  });

  it('[BUG-088] rolls back notification read/read-all optimistically by ID without wiping parallel SSE or paginated items', () => {
    const initial = {
      items: [
        {
          id: 'n-1',
          notificationType: 'ALERT',
          title: 'A',
          body: 'B',
          relatedObjectType: null,
          relatedObjectId: null,
          status: 'UNREAD',
          createdAt: '2026-11-26T01:00:00Z',
          readAt: null,
        },
        {
          id: 'n-2',
          notificationType: 'ALERT',
          title: 'C',
          body: 'D',
          relatedObjectType: null,
          relatedObjectId: null,
          status: 'UNREAD',
          createdAt: '2026-11-26T01:01:00Z',
          readAt: null,
        },
      ],
      unreadCount: 2,
      page: 1,
      hasMore: false,
    };

    const afterRead1 = applyOptimisticMarkRead(initial, 'n-1', '2026-11-26T02:00:00Z');
    // Simulate a new SSE notification arriving while n-1 PATCH is in flight
    const withNewSse = {
      ...afterRead1,
      items: [
        {
          id: 'n-sse',
          notificationType: 'INCIDENT',
          title: 'New SSE',
          body: 'Live',
          relatedObjectType: null,
          relatedObjectId: null,
          status: 'UNREAD',
          createdAt: '2026-11-26T02:00:01Z',
          readAt: null,
        },
        ...afterRead1.items,
      ],
      unreadCount: afterRead1.unreadCount + 1,
    };

    const rolledBack = rollbackOptimisticMarkRead(withNewSse, 'n-1', null);
    assert.equal(rolledBack.items.length, 3, 'Must preserve newly arrived SSE notification');
    assert.equal(rolledBack.items.find((i) => i.id === 'n-1')?.status, 'UNREAD');
    assert.equal(rolledBack.items.find((i) => i.id === 'n-sse')?.status, 'UNREAD');
    assert.equal(rolledBack.unreadCount, 3);

    const changedSet = new Set(['n-1', 'n-2']);
    const afterAll = applyOptimisticMarkAllRead(rolledBack, changedSet, '2026-11-26T02:05:00Z');
    assert.equal(afterAll.items.find((i) => i.id === 'n-sse')?.status, 'UNREAD');
    assert.equal(afterAll.unreadCount, 1);

    const rolledBackAll = rollbackOptimisticMarkAllRead(afterAll, changedSet, new Map(), 0);
    assert.equal(rolledBackAll.unreadCount, 3);
  });

  it('[BUG-090, BUG-093, BUG-094, BUG-097, BUG-105] enforces workspace URL tab sync, 5m role tolerance, CIDR array + rank 0, ref-counted scroll lock & user status actions', () => {
    for (const ws of [
      'app/security/security-workspace.tsx',
      'app/auditor/auditor-workspace.tsx',
      'app/admin/workspace.tsx',
      'app/owner/owner-workspace.tsx',
      'app/reader/reader-workspace.tsx',
    ]) {
      assert.match(
        readWebFile(ws),
        /useWorkspaceTabSync/,
        `${ws} must synchronize ?tab= via useWorkspaceTabSync`,
      );
    }

    assert.equal(CLIENT_PAST_TOLERANCE_MS, 5 * 60_000);
    assert.equal(
      CLEARANCE_OPTIONS.some((opt) => opt.value === 0),
      true,
      'CLEARANCE_OPTIONS must include rank 0 UNCLASSIFIED',
    );
    assert.equal(COMPATIBLE_OPERATORS_BY_TYPE.IP.includes('CIDR_MATCH'), true);

    // Reference-counted body scroll lock with JSDOM-like mock document
    const prevDoc = globalThis.document;
    globalThis.document = { body: { style: { overflow: 'auto' } } };
    try {
      const unlockParent = lockBodyScroll();
      assert.equal(globalThis.document.body.style.overflow, 'hidden');
      const unlockChild = lockBodyScroll();
      assert.equal(getActiveBodyScrollLocks(), 2);

      // Closing nested ConfirmDialog + StrictMode duplicate cleanup must NOT unlock parent modal scroll!
      unlockChild();
      unlockChild();
      assert.equal(getActiveBodyScrollLocks(), 1);
      assert.equal(globalThis.document.body.style.overflow, 'hidden');

      unlockParent();
      assert.equal(getActiveBodyScrollLocks(), 0);
      assert.equal(globalThis.document.body.style.overflow, 'auto');
    } finally {
      globalThis.document = prevDoc;
    }

    assert.equal(matchesUserActionFilter('ACTIVE', 'LOCK'), true);
    assert.equal(matchesUserActionFilter('DISABLED', 'LOCK'), false);
    assert.equal(matchesUserActionFilter('PENDING', 'UNLOCK'), false);
    assert.equal(matchesUserActionFilter('LOCKED', 'UNLOCK'), true);
    assert.equal(matchesUserActionFilter('PENDING', 'REACTIVATE'), true);
    assert.equal(matchesUserActionFilter('DISABLED', 'REACTIVATE'), true);

    const sidebarTsx = readWebFile('components/navigation/app-sidebar.tsx');
    const drawerTsx = readWebFile('components/navigation/home-mobile-drawer.tsx');
    assert.match(sidebarTsx, /matchMedia\(['"]\(min-width:\s*1024px\)['"]\)/);
    assert.match(drawerTsx, /matchMedia\(['"]\(min-width:\s*768px\)['"]\)/);
  });

  it('[BUG-103 & BUG-119] validates upload Step 1 docCode/50MB/double-extension/scope and merges USER + ROLE grants per documentId', () => {
    assert.equal(validateDocumentCodeInput(''), null);
    assert.equal(validateDocumentCodeInput('DOC_2026-01'), null);
    assert.notEqual(validateDocumentCodeInput('-INVALID'), null);

    assert.notEqual(validateUploadFileInput({ name: 'empty.pdf', size: 0 }), null);
    assert.notEqual(validateUploadFileInput({ name: 'huge.pdf', size: 51 * 1024 * 1024 }), null);
    assert.notEqual(validateUploadFileInput({ name: 'malware.pdf.exe', size: 1024 }), null);
    assert.notEqual(validateUploadFileInput({ name: 'macro.js.pdf', size: 1024 }), null);
    assert.equal(validateUploadFileInput({ name: 'clean-report.pdf', size: 4096 }), null);

    const scopedDepts = filterDepartmentsByUploadScope({
      departments: [
        { id: '1', code: 'HQ', name: 'Trụ sở', parentId: null },
        { id: '2', code: 'SEC', name: 'An ninh', parentId: '1' },
        { id: '3', code: 'SUB', name: 'Nhóm SOC', parentId: '2' },
        { id: '4', code: 'FIN', name: 'Tài chính', parentId: '1' },
      ],
      userDepartmentId: '2',
      hasGlobalUploadScope: false,
    });
    assert.deepEqual(
      scopedDepts.map((d) => d.id),
      ['2', '3'],
    );

    const nowMs = Date.parse('2026-11-26T10:00:00Z');
    const mergedGrants = mergeActiveReaderGrants(
      [
        {
          grantId: 'g-role',
          principalType: 'ROLE',
          roleName: 'Người đọc tài liệu',
          grantStatus: 'ACTIVE',
          permissions: ['VIEW'],
          validFrom: '2026-11-20T00:00:00Z',
          validUntil: '2026-12-10T00:00:00Z',
          document: {
            id: 'doc-shared',
            title: 'Báo cáo Chung',
            status: 'ACTIVE',
            classificationLevelCode: 'INTERNAL',
          },
        },
        {
          grantId: 'g-user',
          principalType: 'USER',
          grantStatus: 'ACTIVE',
          permissions: ['DOWNLOAD'],
          validFrom: '2026-11-21T00:00:00Z',
          validUntil: '2026-12-01T00:00:00Z',
          document: {
            id: 'doc-shared',
            title: 'Báo cáo Chung',
            status: 'ACTIVE',
            classificationLevelCode: 'INTERNAL',
          },
        },
      ],
      nowMs,
    );
    assert.equal(mergedGrants.length, 1, 'Must deduplicate multiple grants on the same documentId');
    assert.deepEqual(mergedGrants[0].permissions, ['VIEW', 'DOWNLOAD']);
    assert.equal(
      mergedGrants[0].id,
      'g-user',
      'Must prefer grantId that carries DOWNLOAD permission',
    );
    assert.equal(mergedGrants[0].validUntil, '2026-12-10T00:00:00Z');
    assert.equal(mergedGrants[0].hasDirectAndRoleGrant, true);
  });

  it('[BUG-115, BUG-116, BUG-117, BUG-118] enforces md:hidden mobile cards on all 4 remaining tables, responsive min-h-11 sm:min-h-9, and Promise return in ConfirmDialog', () => {
    for (const rel of [
      'app/security/tabs/audit-integrity-tables.tsx',
      'app/security/tabs/detection-rules-tab.tsx',
      'app/security/tabs/network-dlp-tab.tsx',
      'app/owner/tabs/audit-history-tab.tsx',
      'app/admin/tabs/abac-attributes-panel.tsx',
    ]) {
      const content = readWebFile(rel);
      assert.match(content, /md:hidden/, `${rel} must render md:hidden mobile cards`);
      assert.match(content, /hidden md:block/, `${rel} must pair hidden md:block desktop table`);
    }

    for (const rel of [
      'components/ui/tabs.tsx',
      'app/owner/tabs/grants-tab.tsx',
      'app/security/tabs/watermark-forensics-tab.tsx',
      'app/auditor/tabs/export-queue-tab.tsx',
    ]) {
      assert.match(
        readWebFile(rel),
        /\bmin-h-11\b[^\r\n]*\bsm:min-h-9\b/,
        `${rel} must apply min-h-11 ... sm:min-h-9`,
      );
    }

    const confirmDialogTsx = readWebFile('components/ui/confirm-dialog.tsx');
    assert.doesNotMatch(confirmDialogTsx, /void\s+onConfirm\(\)/);
    assert.match(confirmDialogTsx, /onClick=\{\(\)\s*=>\s*onConfirm\(\)\}/);
  });
});
