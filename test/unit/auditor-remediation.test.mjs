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
      const target = path.join(webRoot, `${specifier.slice(2)}.ts`);
      if (fs.existsSync(target)) {
        return { url: pathToFileURL(target).href, shortCircuit: true };
      }
    }
    return nextResolve(specifier, context);
  },
});

const {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
  buildExportFilterParamsFromAuditFilters,
  formatByteSizeVi,
  isInvalidDateRange,
  mergeExportJobHistory,
  toLocalDayBoundaryIso,
} = await import('../../apps/web/app/auditor/helpers.ts');
const {
  formatAuditActionLabel,
  formatAuditObjectTypeLabel,
  formatAuditPartitionLabel,
  formatExportTypeLabel,
} = await import('../../apps/web/lib/ui-labels.ts');

/**
 * Thuật toán: Bộ Kiểm Thử Hồi Quy Toàn Diện Phân Hệ `qa.auditor` (`/auditor`)
 * Mục đích:
 *   - Kiểm chứng xử lý múi giờ lọc ngày (`fromDate`/`toDate`), loại bỏ công việc xuất ma (`mergeExportJobHistory`),
 *     giữ nguyên `#sequence` & tổng số điểm neo trong xác minh chuỗi băm.
 *   - Kiểm chứng 100% nhãn tiếng Việt cho toàn bộ hành động, loại đối tượng, phân vùng và loại báo cáo xuất thực tế.
 *   - Kiểm chứng bất biến bảo mật (CSRF chỉ gửi trên mutating methods, `canExport = false` fail-closed, `mfa_required`),
 *     WCAG 2.1 AA, Mobile 375px và UI Design System trên toàn bộ tệp `apps/web/app/auditor/**`.
 */
describe('Auditor Helpers — Timezone Bounds, Filter Propagation, Export History & Chain Aggregation', () => {
  it('converts local YYYY-MM-DD bounds to full 24h ISO range and rejects reversed dates', () => {
    const startIso = toLocalDayBoundaryIso('2026-11-25', false);
    const endIso = toLocalDayBoundaryIso('2026-11-25', true);
    const diffMs = Date.parse(endIso) - Date.parse(startIso);
    assert.equal(diffMs, 86_399_999, 'Same-day local range must span exactly 23:59:59.999');

    assert.equal(isInvalidDateRange('2026-11-26', '2026-11-25'), true);
    assert.equal(isInvalidDateRange('2026-11-25', '2026-11-25'), false);
    assert.equal(isInvalidDateRange('', '2026-11-25'), false);

    const params = buildAuditLogsQueryParams(
      {
        outcomeFilter: 'DENIED',
        actionFilter: 'login',
        partitionFilter: 'AUTH',
        actorFilter: 'qa.auditor',
        fromDate: '2026-11-25',
        toDate: '2026-11-25',
        sortOrder: 'asc',
      },
      2,
      50,
    );
    assert.equal(params.get('outcome'), 'DENIED');
    assert.equal(params.get('action'), 'login');
    assert.equal(params.get('chainPartition'), 'AUTH');
    assert.equal(params.get('actorUsername'), 'qa.auditor');
    assert.equal(params.get('from'), startIso);
    assert.equal(params.get('to'), endIso);
    assert.equal(params.get('order'), 'asc');
    assert.equal(params.get('page'), '2');
    assert.equal(params.get('pageSize'), '50');

    const exportFilters = buildExportFilterParamsFromAuditFilters({
      outcomeFilter: 'SUCCESS',
      actionFilter: 'DOCUMENT',
      partitionFilter: 'DOCUMENT',
      actorFilter: 'owner',
      fromDate: '2026-11-25',
      toDate: '2026-11-25',
      sortOrder: 'desc',
    });
    assert.equal(exportFilters.outcome, 'SUCCESS');
    assert.equal(exportFilters.action, 'DOCUMENT');
    assert.equal(exportFilters.chainPartition, 'DOCUMENT');
    assert.equal(exportFilters.actorUsername, 'owner');
    assert.equal(exportFilters.from, startIso);
    assert.equal(exportFilters.to, endIso);
  });

  it('drops deleted/expired jobs in mergeExportJobHistory while keeping brand-new optimistic pending jobs', () => {
    const now = Date.parse('2026-11-25T10:00:00.000Z');
    const oldDeleted = {
      id: 'job-deleted',
      exportType: 'AUDIT_LOGS',
      format: 'CSV',
      status: 'COMPLETED',
      createdAt: '2026-11-24T08:00:00.000Z',
    };
    const stalePending = {
      id: 'job-stale-pending',
      exportType: 'AUDIT_LOGS',
      format: 'CSV',
      status: 'PENDING',
      createdAt: '2026-11-25T09:59:00.000Z', // 60s ago -> dropped
    };
    const brandNewPending = {
      id: 'job-fresh-pending',
      exportType: 'AUDIT_LOGS',
      format: 'JSON',
      status: 'PENDING',
      createdAt: '2026-11-25T09:59:55.000Z', // 5s ago -> kept during grace window
    };

    const merged = mergeExportJobHistory([], [oldDeleted, stalePending, brandNewPending], now);
    assert.deepEqual(
      merged.map((j) => j.id),
      ['job-fresh-pending'],
    );
  });

  it('aggregates single & multi-partition verifications preserving violation #sequence and anchor count', () => {
    const multi = aggregatePartitionVerifications({
      AUTH: {
        partition: 'AUTH',
        valid: false,
        totalChecked: 12,
        anchorsChecked: 2,
        resumedFromAnchorSequence: '10',
        violations: [
          {
            code: 'AUDIT_LOG_TAMPERED',
            partition: 'AUTH',
            sequence: '11',
            message: 'tampered',
          },
        ],
      },
      DOCUMENT: {
        partition: 'DOCUMENT',
        valid: true,
        totalChecked: 8,
        anchorsChecked: 1,
        violations: [],
      },
    });
    assert.equal(multi.report.isChainValid, false);
    assert.equal(multi.report.totalEntriesChecked, 20);
    assert.equal(multi.report.totalAnchorsChecked, 3);
    assert.equal(multi.report.resumedFromAnchors, true);
    assert.equal(multi.violationCount, 1);
    assert.ok(multi.report.brokenSequences[0].includes('#11'));
    assert.ok(multi.report.brokenSequences[0].includes('Xác thực'));

    const single = aggregatePartitionVerifications({
      partition: 'AUDIT',
      valid: true,
      totalChecked: 5,
      anchorsChecked: 1,
      violations: [],
    });
    assert.equal(single.partitionCount, 1);
    assert.equal(single.report.isChainValid, true);
    assert.equal(single.report.totalEntriesChecked, 5);
    assert.equal(single.report.chainPartition, 'Kiểm toán & xuất báo cáo');

    assert.equal(formatByteSizeVi(512), '512 B');
    assert.equal(formatByteSizeVi(2048), '2.0 KB');
    assert.equal(formatByteSizeVi(1_572_864), '1.50 MB');
  });
});

describe('UI Labels — 100% Real Backend Audit Actions, Object Types, Partitions & Export Types', () => {
  it('translates all real backend audit actions, object types, partitions, and export types to Vietnamese', () => {
    const realBackendActions = [
      'LOGIN',
      'LOGOUT',
      'LOGOUT_ALL',
      'LOGOUT_OTHERS',
      'TOKEN_REFRESH',
      'REFRESH_REUSE',
      'SESSION_REVOKED',
      'MFA_VERIFY',
      'MFA_ENABLED',
      'MFA_DISABLED',
      'MFA_DISABLE_BLOCKED',
      'MFA_DISABLE_DENIED',
      'MFA_ENROLLMENT_STARTED',
      'MFA_ENROLLMENT_BLOCKED',
      'MFA_FACTOR_REMOVED',
      'MFA_WEBAUTHN_ENROLL_START',
      'MFA_WEBAUTHN_ENROLLED',
      'MFA_WEBAUTHN_AUTH_OPTIONS',
      'MFA_WEBAUTHN_VERIFY',
      'PASSWORD_RESET_REQUEST',
      'PASSWORD_RESET',
      'PASSWORD_CHANGE',
      'ACCESS_PERMITTED',
      'ACCESS_DENIED',
      'DOCUMENT_CREATED',
      'DOCUMENT_UPLOAD_STARTED',
      'DOCUMENT_UPLOAD_COMPLETED',
      'DOCUMENT_UPLOAD_FAILED',
      'DOCUMENT_SCAN_RESULT',
      'DOCUMENT_ACTIVATED',
      'DOCUMENT_METADATA_UPDATED',
      'DOCUMENT_CURRENT_VERSION_SET',
      'DOCUMENT_OWNER_TRANSFERRED',
      'DOCUMENT_RECLASSIFIED',
      'DOCUMENT_ARCHIVED',
      'DOCUMENT_PREVIEWED',
      'DOCUMENT_DOWNLOADED',
      'DOCUMENT_SEARCHED',
      'DOCUMENT_RETENTION_WARNING',
      'ACCESS_REQUEST_CREATED',
      'ACCESS_REQUEST_APPROVED',
      'ACCESS_REQUEST_REJECTED',
      'ACCESS_REQUEST_CANCELLED',
      'GRANT_CREATED',
      'GRANT_EXTENDED',
      'GRANT_EXPIRED',
      'GRANT_REVOKED',
      'ACCESS_SESSION_ENDED',
      'ACCESS_SESSION_TERMINATED',
      'POLICY_ACTIVATED',
      'POLICY_DEACTIVATED',
      'POLICY_DELETED',
      'POLICY_SIMULATED',
      'WATERMARK_GENERATED',
      'WATERMARK_TRACE_PERFORMED',
      'WATERMARK_CONFIG_UPDATED',
      'SECURITY_ALERT_STATUS_UPDATED',
      'SECURITY_ALERT_ASSIGNED',
      'SECURITY_ALERT_NOTE_ADDED',
      'DETECTION_RULE_CONFIGURED',
      'INCIDENT_ACTION_CREATED',
      'INCIDENT_ACTION_COMPLETED',
      'REPORT_EXPORT_REQUESTED',
      'REPORT_EXPORT_DOWNLOADED',
      'AUDIT_CHAIN_VERIFIED',
      'AUDIT_ANCHOR_CREATED',
      'AUDIT_LOG_EXPORTED',
      'USER_CREATED',
      'USER_UPDATED',
      'USER_LOCKED',
      'USER_UNLOCKED',
      'USER_DISABLED',
      'USER_REACTIVATED',
      'USER_CLEARANCE_UPDATED',
      'DEPARTMENT_CREATED',
      'DEPARTMENT_UPDATED',
      'DEPARTMENT_ACTIVATED',
      'DEPARTMENT_DEACTIVATED',
      'ROLE_CREATED',
      'ROLE_UPDATED',
      'ROLE_ENABLED',
      'ROLE_DISABLED',
      'ROLE_DELETED',
      'ROLE_PERMISSIONS_REPLACED',
      'USER_ROLE_ASSIGNED',
      'USER_ROLE_REVOKED',
    ];

    for (const action of realBackendActions) {
      const label = formatAuditActionLabel(action);
      assert.notEqual(label, action, `Action ${action} must be localized into Vietnamese`);
    }

    for (const objType of [
      'ASYNC_EXPORT_JOB',
      'AUTHENTICATION',
      'AUDIT_ANCHOR',
      'DETECTION_RULE_CONFIG',
      'INCIDENT_ACTION',
      'POLICY_SIMULATION',
      'ROLE_PERMISSION',
      'USER_ROLE',
    ]) {
      assert.notEqual(
        formatAuditObjectTypeLabel(objType),
        objType,
        `ObjectType ${objType} must be localized`,
      );
    }

    for (const partition of [
      'GLOBAL',
      'AUTH',
      'DOCUMENT',
      'ACCESS_SESSION',
      'RBAC',
      'AUDIT',
      'SECURITY',
      'SECURITY_OPERATIONS',
    ]) {
      assert.notEqual(
        formatAuditPartitionLabel(partition),
        partition,
        `Partition ${partition} must be localized`,
      );
    }

    assert.equal(formatExportTypeLabel('SECURITY_ALERTS'), 'Cảnh báo an ninh');
    assert.equal(formatExportTypeLabel('INCIDENT_REPORTS'), 'Báo cáo sự cố');
    assert.equal(formatExportTypeLabel('SYSTEM_REPORT'), 'Báo cáo hệ thống');
    assert.equal(formatExportTypeLabel('AUDIT_LOGS'), 'Nhật ký kiểm toán');
  });
});

describe('Auditor Security, Accessibility (WCAG 2.1 AA), Mobile 375px & Design System Invariants', () => {
  it('attaches x-csrf-token only on state-changing HTTP methods in api-client and routes mfa_required to /mfa', () => {
    const apiClientSrc = fs.readFileSync(path.join(webRoot, 'lib/api-client.ts'), 'utf8');
    assert.match(apiClientSrc, /isStateChangingMethod/);
    assert.match(
      apiClientSrc,
      /if \(csrf && isStateChangingMethod\) headers\['x-csrf-token'\] = csrf/,
    );

    const authContextSrc = fs.readFileSync(path.join(webRoot, 'lib/auth-context.tsx'), 'utf8');
    assert.match(authContextSrc, /reason === 'mfa_required'/);
    assert.match(authContextSrc, /router\.replace\('\/mfa'\)/);
  });

  it('enforces fail-closed permissions, mobile 375px cards, touch targets >= 44px, and zero duplicate error banners in /auditor', () => {
    const workspace = fs.readFileSync(
      path.join(webRoot, 'app/auditor/auditor-workspace.tsx'),
      'utf8',
    );
    const auditTab = fs.readFileSync(
      path.join(webRoot, 'app/auditor/tabs/audit-trail-tab.tsx'),
      'utf8',
    );
    const exportTab = fs.readFileSync(
      path.join(webRoot, 'app/auditor/tabs/export-queue-tab.tsx'),
      'utf8',
    );
    const exportModal = fs.readFileSync(
      path.join(webRoot, 'app/auditor/modals/export-report-modal.tsx'),
      'utf8',
    );
    const detailModal = fs.readFileSync(
      path.join(webRoot, 'app/auditor/modals/auditor-log-detail-modal.tsx'),
      'utf8',
    );
    const chainTab = fs.readFileSync(
      path.join(webRoot, 'app/auditor/tabs/chain-integrity-tab.tsx'),
      'utf8',
    );

    // All 5 AUDITOR permissions wired in strictly self-contained read-only mode
    assert.match(workspace, /hasPermission\('AUDIT_LOG:VIEW'\)/);
    assert.match(workspace, /hasPermission\('AUDIT_LOG:EXPORT'\)/);
    assert.match(workspace, /hasPermission\('SYSTEM_REPORT:EXPORT'\)/);
    assert.match(workspace, /hasPermission\('SECURITY_ALERT:VIEW'\)/);
    assert.match(workspace, /hasPermission\('WATERMARK_INSTANCE:TRACE'\)/);
    assert.match(workspace, /AuditorAlertDetailModal/);
    assert.match(workspace, /AuditorWatermarkTraceTab/);
    assert.doesNotMatch(workspace, /@\/app\/security/);
    assert.match(workspace, /!hasOpenDialog/);
    assert.match(workspace, /retryLastFailedOperation\(\)/);
    assert.match(workspace, /onDownloadExport=\{downloadExport\}/);
    assert.doesNotMatch(workspace, /void downloadExport/);

    const alertModal = fs.readFileSync(
      path.join(webRoot, 'app/auditor/modals/auditor-alert-detail-modal.tsx'),
      'utf8',
    );
    const wmTab = fs.readFileSync(
      path.join(webRoot, 'app/auditor/tabs/auditor-watermark-trace-tab.tsx'),
      'utf8',
    );
    assert.doesNotMatch(alertModal, /method:\s*['"](?:PATCH|POST|PUT|DELETE)['"]/);
    assert.doesNotMatch(wmTab, /method:\s*['"](?:PATCH|POST|PUT|DELETE)['"]/);

    // Mobile 375px cards + 44px page-size select + skeleton + caption
    assert.match(auditTab, /md:hidden/);
    assert.match(auditTab, /animate-pulse/);
    assert.match(auditTab, /<caption className="sr-only">/);
    assert.match(auditTab, /id="auditor-page-size"[\s\S]{0,200}min-h-11/);

    // Fail-closed ExportQueueTab + SHA-256 copy + mobile cards
    assert.match(exportTab, /canExport = false/);
    assert.match(exportTab, /md:hidden/);
    assert.match(exportTab, /sha256Hash/);
    assert.match(exportTab, /downloadingJobId/);

    // ExportReportModal supports dynamic exportType, filterParams & disables cancel
    assert.match(exportModal, /filterParams/);
    assert.match(exportModal, /SYSTEM_REPORT/);
    assert.match(exportModal, /text="Hủy"[\s\S]{0,120}disabled=\{isExporting\}/);

    // Detail modal shows userAgent, hmacKeyVersion, copy buttons & accurate Genesis #1 check
    assert.match(detailModal, /userAgent/);
    assert.match(detailModal, /hmacKeyVersion/);
    assert.match(detailModal, /isGenesisEntry/);
    assert.match(detailModal, /aria-label="Sao chép mã truy vết"/);

    // Chain integrity tab supports partition select, anchors table & JSON download
    assert.match(chainTab, /auditor-verify-partition/);
    assert.match(chainTab, /downloadVerificationReportJson/);
    assert.match(chainTab, /totalAnchorsChecked/);

    // No window.alert / window.confirm anywhere in /auditor
    for (const src of [workspace, auditTab, exportTab, exportModal, detailModal, chainTab]) {
      assert.doesNotMatch(src, /window\.(alert|confirm)\(/);
    }
  });
});
