import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  deriveClassificationCodeFromName,
  filterDiscoverableDocs,
  isActiveReaderGrant,
  mapReaderDocumentDto,
  mapReaderGrantDto,
} from '../../apps/web/app/reader/helpers.ts';
import {
  buildGrantLookupMaps,
  evaluateUploadSubjectReadiness,
  expandGrantPermissions,
  extractAuditPagination,
  formatIsoDateDisplay,
  getMinRetentionDate,
  isClassificationAllowedForClearance,
  mapDocumentDtoToItem,
  mapGrantDtoToItem,
  resolveUploadWizardDefaults,
  validateRetentionDateInput,
} from '../../apps/web/app/owner/helpers.ts';
import {
  filterGrantEligibleUsers,
  filterGrantableDocuments,
  formatGrantPermissionSummary,
  formatUserLookupOptionLabel,
  isUserClearanceRedacted,
  shouldWarnGrantClearance,
  validateDirectGrantTimeRange,
} from '../../apps/web/app/owner/grant-helpers.ts';
import { localizeApiErrorMessage } from '../../apps/web/lib/api-error-messages.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm chứng Hợp đồng Ánh xạ DTO Giao diện (`/reader`, `/owner`), Khung Hộp thoại/Tab WAI-ARIA & Bất biến CSP Proxy
 * Mục đích: Đảm bảo các hàm ánh xạ/lọc DTO thực thi đúng theo cấu trúc dữ liệu máy chủ (`my-grants`, `documents`, `access-grants`, `audit-logs`),
 *   đồng thời kiểm tra tĩnh cấu trúc `DialogContent`, liên kết trợ năng `Tabs`, biểu thức chính quy thủy ấn DLP `{48}` và chính sách `nonce` CSP trong `proxy.ts`.
 * Cơ chế hoạt động: Thực thi trực tiếp các hàm thuần TypeScript trong `O(N)` và đối sánh cú pháp AST/mẫu văn bản trên các tệp thành phần giao diện.
 */
describe('/reader DTO Mappers & Active Grant Filtering Contracts', () => {
  it('maps nested GET /documents/my-grants payloads without literal placeholder IDs and derives download policy', () => {
    assert.equal(deriveClassificationCodeFromName('Nội bộ'), 'INTERNAL');
    assert.equal(deriveClassificationCodeFromName('Mật'), 'CONFIDENTIAL');
    assert.equal(deriveClassificationCodeFromName('Tối mật'), 'SECRET');
    assert.equal(deriveClassificationCodeFromName('Tuyệt mật'), 'TOP_SECRET');

    const confidentialGrant = mapReaderGrantDto({
      grantId: 'grant-uuid-01',
      permissions: ['DOWNLOAD'],
      grantStatus: 'ACTIVE',
      validFrom: '2026-01-01T00:00:00.000Z',
      validUntil: '2099-01-01T00:00:00.000Z',
      document: {
        id: 'doc-uuid-01',
        documentCode: 'DOC-2026-001',
        title: 'Báo cáo Tài chính Mật',
        status: 'ACTIVE',
        classificationLevelName: 'Mật',
      },
    });
    assert.equal(confidentialGrant.id, 'grant-uuid-01');
    assert.equal(confidentialGrant.documentId, 'doc-uuid-01');
    assert.equal(confidentialGrant.title, 'Báo cáo Tài chính Mật');
    assert.equal(confidentialGrant.documentCode, 'DOC-2026-001');
    assert.equal(confidentialGrant.classificationCode, 'CONFIDENTIAL');
    assert.equal(confidentialGrant.allowDownload, true);
    assert.deepEqual(confidentialGrant.permissions, ['VIEW', 'DOWNLOAD']);

    const secretGrant = mapReaderGrantDto({
      grantId: 'grant-uuid-02',
      permissions: ['VIEW'],
      document: { id: 'doc-uuid-02', title: 'Hồ sơ Tối mật', classificationLevelName: 'Tối mật' },
    });
    assert.equal(secretGrant.classificationCode, 'SECRET');
    assert.equal(secretGrant.allowDownload, false);
  });

  it('filters out revoked, expired, future, or non-active-document grants in isActiveReaderGrant', () => {
    const nowMs = Date.parse('2026-06-01T12:00:00.000Z');
    const base = {
      grantStatus: 'ACTIVE',
      validFrom: '2026-06-01T00:00:00.000Z',
      validUntil: '2026-06-08T00:00:00.000Z',
      document: { id: 'd1', status: 'ACTIVE' },
    };
    assert.equal(isActiveReaderGrant(base, nowMs), true);
    assert.equal(isActiveReaderGrant({ ...base, grantStatus: 'REVOKED' }, nowMs), false);
    assert.equal(
      isActiveReaderGrant({ ...base, document: { id: 'd1', status: 'ARCHIVED' } }, nowMs),
      false,
    );
    assert.equal(
      isActiveReaderGrant({ ...base, validFrom: '2026-06-02T00:00:00.000Z' }, nowMs),
      false,
    );
    assert.equal(
      isActiveReaderGrant({ ...base, validUntil: '2026-06-01T12:00:00.000Z' }, nowMs),
      false,
    );
  });

  it('aligns flat catalog search DTOs and treats INTERNAL & RESTRICTED equivalently when filtering', () => {
    const internalDoc = mapReaderDocumentDto({
      id: 'd-int',
      title: 'Quy trình Nội bộ',
      documentCode: 'QT-01',
      classificationLevelCode: 'INTERNAL',
      departmentName: 'Phòng Nhân sự',
    });
    const restrictedDoc = mapReaderDocumentDto({
      id: 'd-res',
      title: 'Phụ lục Hạn chế',
      classificationCode: 'RESTRICTED',
      departmentName: 'Phòng Pháp chế',
    });
    const topSecretDoc = mapReaderDocumentDto({
      id: 'd-ts',
      title: 'Chiến lược Tuyệt mật',
      classificationLevelCode: 'TOP_SECRET',
    });

    assert.equal(internalDoc.allowDownload, true);
    assert.equal(internalDoc.departmentName, 'Phòng Nhân sự');
    assert.equal(topSecretDoc.allowDownload, false);

    const filtered = filterDiscoverableDocs(
      [internalDoc, restrictedDoc, topSecretDoc],
      '',
      'INTERNAL',
    );
    assert.deepEqual(
      filtered.map((d) => d.id),
      ['d-int', 'd-res'],
    );

    const catalogTab = fs.readFileSync(
      path.join(webRoot, 'app/reader/tabs/catalog-tab.tsx'),
      'utf8',
    );
    assert.match(catalogTab, /<option\s+value="INTERNAL">/);
  });
});

describe('/owner DTO Mappers, Permission Inclusion, Pagination & Wizard Defaults', () => {
  it('derives Bell-LaPadula rank and allowDownload accurately from flat classificationLevelCode', () => {
    const unclass = mapDocumentDtoToItem({ id: '1', classificationLevelCode: 'UNCLASSIFIED' });
    const internal = mapDocumentDtoToItem({
      id: '2',
      classificationLevelCode: 'INTERNAL',
      departmentName: 'Khối Công nghệ',
    });
    const confidential = mapDocumentDtoToItem({ id: '3', classificationLevelCode: 'CONFIDENTIAL' });
    const secret = mapDocumentDtoToItem({ id: '4', classificationLevelCode: 'SECRET' });

    assert.equal(unclass.classificationRank, 0);
    assert.equal(unclass.allowDownload, true);
    assert.equal(internal.classificationRank, 1);
    assert.equal(internal.allowDownload, true);
    assert.equal(internal.departmentName, 'Khối Công nghệ');
    assert.equal(confidential.classificationRank, 2);
    assert.equal(confidential.allowDownload, true);
    assert.equal(secret.classificationRank, 3);
    assert.equal(secret.allowDownload, false);
  });

  it('expands DOWNLOAD grants to include VIEW, reads nested audit pagination, and resolves lookup names', () => {
    assert.deepEqual(expandGrantPermissions('DOWNLOAD'), ['VIEW', 'DOWNLOAD']);
    assert.deepEqual(expandGrantPermissions(['DOWNLOAD']), ['VIEW', 'DOWNLOAD']);
    assert.deepEqual(expandGrantPermissions('VIEW'), ['VIEW']);

    assert.deepEqual(
      extractAuditPagination({ pagination: { page: 3, totalPages: 9, total: 130 } }),
      { page: 3, totalPages: 9, total: 130 },
    );

    const lookups = buildGrantLookupMaps(
      [{ id: 'doc-9', title: 'Kế hoạch An ninh 2026' }],
      [{ id: '42', fullName: 'Trần Thị B', username: 'tranthib' }],
      [{ id: '7', name: 'Người đọc tài liệu', code: 'DOCUMENT_READER' }],
    );
    const userGrant = mapGrantDtoToItem(
      { id: 'g1', documentId: 'doc-9', principalType: 'USER', principalUserId: '42' },
      lookups,
    );
    const roleGrant = mapGrantDtoToItem(
      { id: 'g2', documentId: 'doc-9', principalType: 'ROLE', principalRoleId: '7' },
      lookups,
    );
    assert.equal(userGrant.documentTitle, 'Kế hoạch An ninh 2026');
    assert.equal(userGrant.principalName, 'Trần Thị B');
    assert.equal(roleGrant.principalName, 'Người đọc tài liệu');

    const defaults = resolveUploadWizardDefaults({
      userDepartmentId: '5',
      departments: [
        { id: 2, code: 'FIN', name: 'Tài chính' },
        { id: 5, code: 'ENG', name: 'Kỹ thuật' },
      ],
      businessCategories: [{ id: 11, code: 'OPS', name: 'Vận hành', departmentId: 5 }],
      classificationLevels: [
        {
          id: 1,
          code: 'INTERNAL',
          name: 'Nội bộ',
          rank: 1,
          allowDownload: true,
          requireWatermark: true,
        },
        {
          id: 2,
          code: 'CONFIDENTIAL',
          name: 'Mật',
          rank: 2,
          allowDownload: true,
          requireWatermark: true,
        },
      ],
    });
    assert.deepEqual(defaults, { departmentId: 5, categoryId: 11, classificationId: 2 });
  });

  it('validates retention dates against past selection and wires min + Step 3 review in upload wizard', () => {
    const refDate = new Date('2026-11-25T12:00:00.000Z');
    const minDate = getMinRetentionDate(refDate);
    assert.equal(minDate, '2026-11-25');
    assert.equal(formatIsoDateDisplay('2026-11-25'), '25/11/2026');
    assert.equal(validateRetentionDateInput('', refDate), null);
    assert.equal(validateRetentionDateInput('2026-11-25', refDate), null);
    assert.equal(validateRetentionDateInput('2026-12-31', refDate), null);
    assert.match(validateRetentionDateInput('2026-11-24', refDate) ?? '', /quá khứ/);
    assert.match(validateRetentionDateInput('2026-02-31', refDate) ?? '', /không hợp lệ/);

    const policyReviewTsx = fs.readFileSync(
      path.join(webRoot, 'app/owner/modals/upload-step-policy-review.tsx'),
      'utf8',
    );
    assert.match(policyReviewTsx, /min=\{minRetentionDate\}/);
    assert.match(policyReviewTsx, /Thời hạn lưu trữ:/);

    const uploadModalTsx = fs.readFileSync(
      path.join(webRoot, 'app/owner/modals/upload-document-modal.tsx'),
      'utf8',
    );
    assert.match(uploadModalTsx, /Boolean\(retentionDateError\)/);
    assert.match(uploadModalTsx, /onClick=\{handleNextStep\}/);
  });

  it('enforces Bell-LaPadula clearance gating on Step 1 upload wizard defaults and controls', () => {
    assert.equal(isClassificationAllowedForClearance(3, 3), true);
    assert.equal(isClassificationAllowedForClearance(4, 3), false);
    assert.equal(isClassificationAllowedForClearance(1, 0), false);
    assert.equal(isClassificationAllowedForClearance(4, undefined), true);

    const limitedDefaults = resolveUploadWizardDefaults({
      userDepartmentId: '5',
      userClearanceRank: 1,
      departments: [{ id: 5, code: 'ENG', name: 'Kỹ thuật' }],
      businessCategories: [{ id: 11, code: 'OPS', name: 'Vận hành', departmentId: 5 }],
      classificationLevels: [
        {
          id: 1,
          code: 'INTERNAL',
          name: 'Nội bộ',
          rank: 1,
          allowDownload: true,
          requireWatermark: true,
        },
        {
          id: 2,
          code: 'CONFIDENTIAL',
          name: 'Mật',
          rank: 2,
          allowDownload: true,
          requireWatermark: true,
        },
        {
          id: 3,
          code: 'SECRET',
          name: 'Tối mật',
          rank: 3,
          allowDownload: false,
          requireWatermark: true,
        },
      ],
    });
    assert.equal(limitedDefaults.classificationId, 1);

    const stepMetadataTsx = fs.readFileSync(
      path.join(webRoot, 'app/owner/modals/upload-step-metadata.tsx'),
      'utf8',
    );
    assert.match(stepMetadataTsx, /isClassificationAllowedForClearance/);
    assert.match(stepMetadataTsx, /disabled=\{isAboveClearance\}/);
    assert.match(stepMetadataTsx, /subjectReadiness\.missingDepartment/);
  });

  it('validates ABAC subject readiness before upload, requires department on user modals, and distinguishes ABAC denial reasons', () => {
    const missingDept = evaluateUploadSubjectReadiness({
      departmentId: null,
      clearanceRank: 3,
      status: 'ACTIVE',
    });
    assert.equal(missingDept.ready, false);
    assert.equal(missingDept.missingDepartment, true);
    assert.equal(missingDept.missingClearance, false);
    assert.match(missingDept.blockingReason ?? '', /phòng ban trực thuộc/i);

    const missingClearance = evaluateUploadSubjectReadiness({
      departmentId: '9',
      clearanceRank: 0,
      status: 'ACTIVE',
    });
    assert.equal(missingClearance.ready, false);
    assert.equal(missingClearance.missingClearance, true);
    assert.match(missingClearance.blockingReason ?? '', /cấp thẩm quyền bảo mật/i);

    const readySubject = evaluateUploadSubjectReadiness({
      departmentId: '9',
      clearanceRank: 3,
      status: 'ACTIVE',
    });
    assert.equal(readySubject.ready, true);
    assert.equal(readySubject.blockingReason, null);

    const specificMissingDeptMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: MISSING_REQUIRED_ATTRIBUTE (SUBJECT_DEPARTMENT)',
      details: {
        reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
        missingAttributes: ['SUBJECT_DEPARTMENT'],
      },
    });
    assert.match(specificMissingDeptMsg, /phòng ban trực thuộc/i);

    const genericMissingAttrMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: MISSING_REQUIRED_ATTRIBUTE',
    });
    assert.match(genericMissingAttrMsg, /thuộc tính bắt buộc \(phòng ban hoặc cấp thẩm tra\)/i);

    const explicitDenyMsg = localizeApiErrorMessage(403, {
      errorCode: 'POLICY_DENIED',
      message: 'Access denied by policy: EXPLICIT_DENY',
    });
    assert.match(explicitDenyMsg, /MFA|rủi ro/i);

    const grantMissingDeptMsg = localizeApiErrorMessage(403, {
      errorCode: 'GRANT_ABAC_DENIED',
      message: 'ABAC policy denied VIEW access: MISSING_REQUIRED_ATTRIBUTE (SUBJECT_DEPARTMENT).',
    });
    assert.match(grantMissingDeptMsg, /Đối tượng nhận quyền.*phòng ban trực thuộc/i);

    const roleGrantClearanceMsg = localizeApiErrorMessage(403, {
      errorCode: 'GRANT_CLEARANCE_INSUFFICIENT',
      message:
        'Target role holders do not all satisfy the clearance level required for this document classification.',
    });
    assert.match(roleGrantClearanceMsg, /vai trò này.*thành viên.*cấp thẩm quyền bảo mật/i);

    const createUserModalTsx = fs.readFileSync(
      path.join(webRoot, 'app/admin/modals/create-user-modal.tsx'),
      'utf8',
    );
    const editUserModalTsx = fs.readFileSync(
      path.join(webRoot, 'app/admin/modals/edit-user-modal.tsx'),
      'utf8',
    );
    for (const [name, src] of [
      ['create-user-modal.tsx', createUserModalTsx],
      ['edit-user-modal.tsx', editUserModalTsx],
    ]) {
      assert.doesNotMatch(src, /Không gán phòng ban/, `${name} must require department selection`);
      assert.match(src, /id="(?:modal|edit-user)-department"[\s\S]{0,80}\brequired\b/);
    }
  });

  it('scopes /owner queries strictly to owned resources and uses production-ready preview copy without Sandbox, sess-active, Gotenberg, or Fail-Closed UI text', () => {
    const ownerDataTs = fs.readFileSync(
      path.join(webRoot, 'app/owner/hooks/use-owner-data.ts'),
      'utf8',
    );
    assert.match(ownerDataTs, /\/documents\?scope=owned&pageSize=50/);
    assert.match(ownerDataTs, /\/access-grants\?scope=owned&pageSize=50/);

    const uiFilesToAudit = [
      'components/documents/shared-pdf-preview-modal.tsx',
      'app/owner/modals/forensic-preview-modal.tsx',
      'app/owner/modals/upload-step-policy-review.tsx',
      'app/owner/hooks/use-owner-delivery.ts',
      'app/reader/modals/document-viewer-modal.tsx',
      'app/reader/hooks/use-reader-viewer.ts',
      'app/security/tabs/watermark-forensics-tab.tsx',
    ];
    for (const relPath of uiFilesToAudit) {
      const content = fs.readFileSync(path.join(webRoot, relPath), 'utf8');
      assert.doesNotMatch(content, /sess-active/, `${relPath} must not fabricate sess-active`);
      assert.doesNotMatch(content, /Gotenberg/, `${relPath} must not leak Gotenberg in UI`);
      assert.doesNotMatch(
        content,
        /Sandbox Xem Trước|Đóng Sandbox|Secure Sandbox/,
        `${relPath} must not display Sandbox labels to end users`,
      );
      assert.doesNotMatch(
        content,
        /\([^)]*Fail-Closed[^)]*\)/,
        `${relPath} must not display Fail-Closed jargon in user-facing messages`,
      );
    }

    const previewModal = fs.readFileSync(
      path.join(webRoot, 'components/documents/shared-pdf-preview-modal.tsx'),
      'utf8',
    );
    assert.match(previewModal, /Xem tài liệu bảo mật:/);
    assert.match(previewModal, /Đang khởi tạo phiên truy cập/);
    assert.match(previewModal, /Chế độ xem bảo mật · Có gắn (?:dấu Watermark|watermark bảo mật)/);
    assert.match(previewModal, /text="Đóng"/);
  });

  it('enforces direct grant filters, REDACTED clearance handling, unified permission labels, 30-day/future bounds, and GrantsTab controls', () => {
    const activeDoc = mapDocumentDtoToItem({
      id: 'd-active',
      title: 'Báo cáo tài chính quý 3/2026',
      classificationLevelCode: 'SECRET',
      status: 'ACTIVE',
    });
    const draftDoc = mapDocumentDtoToItem({
      id: 'd-draft',
      title: 'Bản nháp nội bộ',
      classificationLevelCode: 'INTERNAL',
      status: 'DRAFT',
    });
    const archivedDoc = mapDocumentDtoToItem({
      id: 'd-arch',
      title: 'Hồ sơ lưu trữ',
      classificationLevelCode: 'CONFIDENTIAL',
      status: 'ARCHIVED',
    });
    assert.deepEqual(
      filterGrantableDocuments([activeDoc, draftDoc, archivedDoc]).map((d) => d.id),
      ['d-active'],
    );

    const eligibleUsers = filterGrantEligibleUsers(
      [
        {
          id: '10',
          username: 'athanhnee',
          fullName: 'Đặng Minh Thành',
          departmentName: 'Khối văn phòng',
          clearanceRank: 3,
        },
        {
          id: '11',
          username: 'reader.other',
          fullName: 'Nguyễn Văn A',
          departmentName: 'Phòng Tài chính',
          clearanceRank: 0,
          clearanceCode: 'REDACTED',
        },
      ],
      '10',
    );
    assert.deepEqual(
      eligibleUsers.map((u) => u.id),
      ['11'],
    );
    assert.equal(isUserClearanceRedacted(eligibleUsers[0]), true);
    assert.match(formatUserLookupOptionLabel(eligibleUsers[0]), /Độ mật ẩn/);
    assert.doesNotMatch(formatUserLookupOptionLabel(eligibleUsers[0]), /Cấp 0/);
    assert.equal(
      shouldWarnGrantClearance({
        principalType: 'USER',
        document: activeDoc,
        user: eligibleUsers[0],
      }),
      false,
    );
    assert.equal(
      shouldWarnGrantClearance({
        principalType: 'USER',
        document: activeDoc,
        user: { clearanceRank: 1, clearanceCode: 'INTERNAL' },
      }),
      true,
    );

    assert.deepEqual(formatGrantPermissionSummary(['VIEW', 'DOWNLOAD']), {
      label: 'Xem & Tải về',
      includesDownload: true,
    });
    assert.deepEqual(formatGrantPermissionSummary(['VIEW']), {
      label: 'Chỉ xem',
      includesDownload: false,
    });

    const refNow = new Date('2026-11-25T07:00:00.000Z');
    assert.equal(
      validateDirectGrantTimeRange('2026-11-25T07:00:00.000Z', '2026-12-02T07:00:00.000Z', {
        now: refNow,
      }),
      null,
    );
    assert.match(
      validateDirectGrantTimeRange('2026-11-20T07:00:00.000Z', '2026-11-24T07:00:00.000Z', {
        now: refNow,
      }) ?? '',
      /hiện tại/i,
    );
    assert.match(
      validateDirectGrantTimeRange('2026-11-25T07:00:00.000Z', '2027-01-10T07:00:00.000Z', {
        now: refNow,
      }) ?? '',
      /tối đa là 30 ngày/i,
    );

    const createGrantModalTsx = fs.readFileSync(
      path.join(webRoot, 'app/owner/modals/create-grant-modal.tsx'),
      'utf8',
    );
    assert.match(createGrantModalTsx, /disabled=\{!canDownloadSelectedDoc\}/);
    assert.match(createGrantModalTsx, /<legend[^>]*>Quyền được cấp<\/legend>/);
    assert.match(createGrantModalTsx, /min=\{minValidUntil\}/);
    assert.match(createGrantModalTsx, /max=\{maxValidUntil\}/);
    assert.match(createGrantModalTsx, /disabled=\{isSubmitBlocked\}/);

    const grantsTabTsx = fs.readFileSync(
      path.join(webRoot, 'app/owner/tabs/grants-tab.tsx'),
      'utf8',
    );
    assert.match(grantsTabTsx, /formatGrantPermissionSummary/);
    assert.match(grantsTabTsx, /includeTime:\s*true/);
    assert.match(grantsTabTsx, /Trang trước/);
    assert.match(grantsTabTsx, /Trang sau/);
    assert.match(grantsTabTsx, /Lọc trạng thái quyền truy cập/);
  });
});

describe('Dialog Sizing, Tabs ARIA Linkage, DLP Regex Escaping & CSP Proxy Invariants', () => {
  it('places default max-w-lg on DialogContent rather than squeezing children inside Dialog wrapper', () => {
    const dialogTsx = fs.readFileSync(path.join(webRoot, 'components/ui/dialog.tsx'), 'utf8');
    const [dialogPart, dialogContentPart = ''] = dialogTsx.split('export function DialogContent');
    assert.doesNotMatch(dialogPart, /\bmax-w-(?:sm|md|lg|xl|2xl)\b/);
    assert.match(dialogContentPart, /\bmax-w-lg\b/);
  });

  it('links TabsTrigger and TabsContent via aria-controls and aria-labelledby', () => {
    const tabsTsx = fs.readFileSync(path.join(webRoot, 'components/ui/tabs.tsx'), 'utf8');
    assert.match(tabsTsx, /role="tablist"/);
    assert.match(tabsTsx, /role="tab"/);
    assert.match(tabsTsx, /role="tabpanel"/);
    assert.match(tabsTsx, /\baria-controls=/);
    assert.match(tabsTsx, /\baria-labelledby=/);
  });

  it('does not leak proxy configuration, loopback ICAP ports, or raw regex patterns in network-dlp-overview.tsx', () => {
    const dlpTsx = fs.readFileSync(
      path.join(webRoot, 'app/security/tabs/network-dlp-overview.tsx'),
      'utf8',
    );
    assert.doesNotMatch(dlpTsx, /squid\.conf/i);
    assert.doesNotMatch(dlpTsx, /127\.0\.0\.1:1344/);
    assert.doesNotMatch(dlpTsx, /icap:\/\//i);
    assert.doesNotMatch(dlpTsx, /WM-\[a-f0-9\]\{48\}/);
  });

  it('enforces per-request CSP nonce without prefetch header exclusion in proxy.ts', () => {
    const proxyTs = fs.readFileSync(path.join(webRoot, 'proxy.ts'), 'utf8');
    assert.doesNotMatch(proxyTs, /next-router-prefetch/);
    assert.doesNotMatch(proxyTs, /unsafe-inline/);
    assert.match(proxyTs, /NODE_ENV\s*===\s*['"]development['"]/);
    assert.match(proxyTs, /'nonce-\$\{nonce\}'/);
    assert.match(proxyTs, /frame-ancestors 'none'/);
    assert.match(proxyTs, /object-src 'none'/);
    assert.match(proxyTs, /['"]x-nonce['"]/);
  });
});
