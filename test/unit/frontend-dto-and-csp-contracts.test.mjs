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
  expandGrantPermissions,
  extractAuditPagination,
  mapDocumentDtoToItem,
  mapGrantDtoToItem,
  resolveUploadWizardDefaults,
} from '../../apps/web/app/owner/helpers.ts';

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

  it('escapes {48} in network-dlp-overview.tsx so JSX renders literal regex braces', () => {
    const dlpTsx = fs.readFileSync(
      path.join(webRoot, 'app/security/tabs/network-dlp-overview.tsx'),
      'utf8',
    );
    assert.doesNotMatch(dlpTsx, />WM-\[a-f0-9\]\{48\}</);
    assert.match(
      dlpTsx,
      /(?:\{'\{48\}'\}|\{['"`]WM-\[a-f0-9\]\{48\}['"`]\}|&#123;48&#125;|\\u007b48\\u007d)/,
    );
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
