import assert from 'node:assert/strict';
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (
      (specifier.startsWith('./') || specifier.startsWith('../')) &&
      !path.extname(specifier) &&
      context.parentURL?.startsWith('file:')
    ) {
      const candidate = new URL(`${specifier}.ts`, context.parentURL);
      if (fs.existsSync(fileURLToPath(candidate))) {
        return nextResolve(candidate.href, context);
      }
    }
    return nextResolve(specifier, context);
  },
});

const { inferAllowDownloadFromClassificationCode, mapDocumentDtoToItem } =
  await import('../../apps/web/app/owner/helpers.ts');
const {
  applyCancelledRequestToFilteredPage,
  applyCreatedRequestToFilteredPage,
  buildActiveGrantsByDocId,
  extractPendingRequestDocIds,
} = await import('../../apps/web/app/reader/helpers.ts');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');
const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const readWeb = (rel) => stripComments(fs.readFileSync(path.join(webRoot, rel), 'utf8'));

describe('BUG-020 through BUG-029 Frontend Logic & Structural Invariants', () => {
  it('[BUG-020] appends text fields (documentId, changeNote) to FormData strictly BEFORE file in handleConfirmNewVersion', () => {
    const lifecycleHook = readWeb('app/owner/hooks/use-document-lifecycle.ts');
    const [, fnBody = ''] = lifecycleHook.split('async function handleConfirmNewVersion');
    const docIdIdx = fnBody.indexOf("formData.append('documentId'");
    const changeNoteIdx = fnBody.indexOf("formData.append('changeNote'");
    const fileIdx = fnBody.indexOf("formData.append('file'");

    assert.ok(docIdIdx > -1 && changeNoteIdx > -1 && fileIdx > -1);
    assert.ok(docIdIdx < fileIdx, 'documentId must be appended before file');
    assert.ok(changeNoteIdx < fileIdx, 'changeNote must be appended before file');
  });

  it('[BUG-021] enforces fail-closed previewAllowDownload + obligations in both viewers and SharedPdfPreviewModal without mutating doc items', () => {
    const sharedModal = readWeb('components/documents/shared-pdf-preview-modal.tsx');
    const readerViewer = readWeb('app/reader/hooks/use-reader-viewer.ts');
    const ownerDelivery = readWeb('app/owner/hooks/use-owner-delivery.ts');
    const readerModal = readWeb('app/reader/modals/document-viewer-modal.tsx');
    const forensicModal = readWeb('app/owner/modals/forensic-preview-modal.tsx');

    assert.match(sharedModal, /obligations\s*=\s*\[\]/);
    assert.match(
      sharedModal,
      /const effectiveAllowDownload = Boolean\(allowDownload\) && !obligations\.includes\('FORBID_DOWNLOAD'\)/,
    );
    assert.doesNotMatch(sharedModal, /window\.alert/);

    assert.match(
      readerViewer,
      /const \[previewAllowDownload, setPreviewAllowDownload\] = useState\(false\)/,
    );
    assert.match(readerViewer, /doc\.permissions\.includes\('DOWNLOAD'\)/);
    assert.match(readerViewer, /hasPermission\('DOCUMENT:DOWNLOAD'\)/);
    assert.match(readerViewer, /!obligations\.includes\('FORBID_DOWNLOAD'\)/);
    assert.doesNotMatch(readerViewer, /previewDoc\.allowDownload\s*=/);
    assert.doesNotMatch(readerViewer, /doc\.allowDownload\s*=/);

    assert.match(
      ownerDelivery,
      /const \[previewAllowDownload, setPreviewAllowDownload\] = useState\(false\)/,
    );
    assert.match(ownerDelivery, /hasPermission\('DOCUMENT:DOWNLOAD'\)/);
    assert.match(ownerDelivery, /!obligations\.includes\('FORBID_DOWNLOAD'\)/);
    assert.doesNotMatch(ownerDelivery, /previewDoc\.allowDownload\s*=/);
    assert.doesNotMatch(ownerDelivery, /doc\.allowDownload\s*=/);

    assert.match(readerModal, /allowDownload=\{previewAllowDownload\}/);
    assert.match(readerModal, /obligations=\{previewObligations\}/);
    assert.match(forensicModal, /allowDownload = false/);
    assert.match(forensicModal, /obligations=\{obligations\}/);
  });

  it('[BUG-022] infers allowDownload fail-closed and preserves temporary empty string in #grant-duration without reintroducing <select>', () => {
    assert.equal(inferAllowDownloadFromClassificationCode(undefined), false);
    assert.equal(inferAllowDownloadFromClassificationCode(null), false);
    assert.equal(inferAllowDownloadFromClassificationCode(''), false);
    assert.equal(inferAllowDownloadFromClassificationCode('SECRET'), false);
    assert.equal(inferAllowDownloadFromClassificationCode('TOP_SECRET'), false);
    assert.equal(inferAllowDownloadFromClassificationCode('CONFIDENTIAL'), true);
    assert.equal(inferAllowDownloadFromClassificationCode('INTERNAL'), true);

    const ownerRequests = readWeb('app/owner/hooks/use-owner-requests.ts');
    const decideModal = readWeb('app/owner/modals/decide-request-modal.tsx');

    assert.doesNotMatch(ownerRequests, /\?\?\s*true/);
    assert.doesNotMatch(decideModal, /\?\?\s*true/);
    assert.doesNotMatch(decideModal, /<select\b/);
    assert.match(decideModal, /draftDaysInput/);
    assert.match(decideModal, /raw\.trim\(\) === ''/);
  });

  it('[BUG-023] loads active owned documents gated by DOCUMENT:DISCOVER when opening CreateGrantModal directly on /owner?tab=grants', () => {
    const ownerData = readWeb('app/owner/hooks/use-owner-data.ts');
    const ownerGrants = readWeb('app/owner/hooks/use-owner-grants.ts');
    const createGrantModal = readWeb('app/owner/modals/create-grant-modal.tsx');

    assert.match(ownerData, /\/documents\?scope=owned&status=ACTIVE&pageSize=50/);
    assert.match(ownerData, /if \(!canDiscoverDocs\)/);
    assert.match(ownerGrants, /ensureGrantDocuments\(\)\.then/);
    assert.match(ownerGrants, /resolveInitialGrantUntil\(firstLoadedDoc,\s*now\)/);
    assert.match(createGrantModal, /Đang tải danh sách tài liệu…/);
  });

  it('[BUG-024 & BUG-025] tracks failedPage for retry without advancing previewPage prematurely, and keeps PDF <canvas> mounted on renderError', () => {
    const readerViewer = readWeb('app/reader/hooks/use-reader-viewer.ts');
    const ownerDelivery = readWeb('app/owner/hooks/use-owner-delivery.ts');
    const canvasViewer = readWeb('components/documents/secure-pdf-canvas-viewer.tsx');

    for (const src of [readerViewer, ownerDelivery]) {
      assert.match(src, /const \[failedPage, setFailedPage\] = useState<number \| null>\(null\)/);
      assert.match(src, /handlePageChange\(failedPage \?\? previewPage\)/);
      const [, pageFn = ''] = src.split('async function handlePageChange');
      const dlIdx = pageFn.indexOf('await apiDownload');
      const setPageIdx = pageFn.indexOf('setPreviewPage(newPage)');
      const setFailedIdx = pageFn.indexOf('setFailedPage(newPage)');
      assert.ok(
        dlIdx > -1 && setPageIdx > dlIdx,
        'setPreviewPage(newPage) must run after apiDownload',
      );
      assert.ok(setFailedIdx > setPageIdx, 'setFailedPage(newPage) must run in catch block');
    }

    assert.match(canvasViewer, /const \[retryCount, setRetryCount\] = useState\(0\)/);
    assert.match(canvasViewer, /\[pdfBytes,\s*zoomScale,\s*containerWidth,\s*retryCount\]/);
    assert.match(canvasViewer, /renderError \? 'hidden'/);
    assert.match(canvasViewer, /Thử kết xuất lại/);
  });

  it('[BUG-026] maps currentVersionNo and versionCount accurately in mapDocumentDtoToItem and renders Phiên bản v{currentVersionNo}', () => {
    const mapped = mapDocumentDtoToItem({
      id: 'doc-v4',
      title: 'Quy trình ứng cứu sự cố',
      documentCode: 'DOC-IR-04',
      classificationLevelCode: 'SECRET',
      currentVersionNo: 4,
      versionCount: 4,
    });
    assert.equal(mapped.currentVersionNo, 4);
    assert.equal(mapped.versionCount, 4);

    const docsTab = readWeb('app/owner/tabs/documents-tab.tsx');
    assert.match(docsTab, /Phiên bản v/);
    assert.match(docsTab, /doc\.currentVersionNo \?\? doc\.versionCount \?\? 1/);
  });

  it('[BUG-027] aligns Owner UI buttons, tab visibility, background lookups, SSE listeners, and empty-tab guidance 1-to-1 with Backend @RequirePermission', () => {
    const docsTab = readWeb('app/owner/tabs/documents-tab.tsx');
    const ownerWorkspace = readWeb('app/owner/owner-workspace.tsx');
    const ownerData = readWeb('app/owner/hooks/use-owner-data.ts');

    assert.match(docsTab, /doc\.status === 'DRAFT' && canClassify/);
    assert.doesNotMatch(docsTab, /doc\.status === 'DRAFT' && canManage/);
    assert.match(docsTab, /const canUploadNewVersion = canUpload && canCreateVersion/);
    // CONFLICT-RESOLVED: Mở 3 nút vòng đời (Phiên bản mới, Phân loại lại, Lưu trữ) cho cả ACTIVE và DRAFT theo BUG-101 tránh kẹt tài liệu nháp.
    assert.match(
      docsTab,
      /const canMutateLifecycle = doc\.status === 'ACTIVE' \|\| doc\.status === 'DRAFT'/,
    );
    assert.match(docsTab, /canMutateLifecycle && canUploadNewVersion/);

    assert.match(
      ownerWorkspace,
      /const canCreateVersion = canUpload && hasPermission\('DOCUMENT_VERSION:CREATE'\)/,
    );
    assert.match(ownerWorkspace, /const canViewRequests = canDecideRequest/);
    assert.match(ownerWorkspace, /const canViewGrants = hasPermission\('ACCESS_GRANT:VIEW'\)/);
    assert.match(ownerWorkspace, /const canViewDocsTab = hasPermission\('DOCUMENT:DISCOVER'\)/);
    assert.match(ownerWorkspace, /permittedTabs\.length === 0/);
    assert.match(ownerWorkspace, /overflow-x-auto/);

    assert.match(ownerData, /if \(!canViewRequests\) return;/);
    assert.match(ownerData, /canLookupUsers/);
    assert.match(ownerData, /canLookupRoles/);
  });

  it('[BUG-028] isolates pendingRequestDocIds and activeGrantsByDocId from paginated/filtered state and respects pageSize <= 50', () => {
    const nowMs = Date.parse('2026-11-26T10:00:00.000Z');
    const grantsMap = buildActiveGrantsByDocId(
      [
        {
          grantId: 'g-view',
          grantStatus: 'ACTIVE',
          validFrom: '2026-11-20T00:00:00.000Z',
          validUntil: '2026-12-01T00:00:00.000Z',
          permissions: ['VIEW'],
          document: { id: 'doc-1', title: 'Tài liệu 1', status: 'ACTIVE' },
        },
        {
          grantId: 'g-dl',
          grantStatus: 'ACTIVE',
          validFrom: '2026-11-20T00:00:00.000Z',
          validUntil: '2026-11-29T00:00:00.000Z',
          permissions: ['VIEW', 'DOWNLOAD'],
          document: { id: 'doc-1', title: 'Tài liệu 1', status: 'ACTIVE' },
        },
        {
          grantId: 'g-expired',
          grantStatus: 'ACTIVE',
          validFrom: '2026-11-01T00:00:00.000Z',
          validUntil: '2026-11-25T00:00:00.000Z',
          permissions: ['VIEW'],
          document: { id: 'doc-2', title: 'Tài liệu 2', status: 'ACTIVE' },
        },
      ],
      nowMs,
    );
    assert.equal(grantsMap.size, 1);
    assert.deepEqual(grantsMap.get('doc-1')?.permissions, ['VIEW', 'DOWNLOAD']);

    const pendingSet = extractPendingRequestDocIds([
      { id: 'r-1', documentId: 'doc-pending', status: 'PENDING' },
      { id: 'r-2', documentId: 'doc-rejected', status: 'REJECTED' },
    ]);
    assert.equal(pendingSet.has('doc-pending'), true);
    assert.equal(pendingSet.has('doc-rejected'), false);

    // Creating a new PENDING request while viewing REJECTED filter must NOT pollute myRequests or requestsTotal
    const rejectedList = [
      {
        id: 'r-rej-1',
        documentId: 'doc-9',
        documentTitle: 'Tài liệu bị từ chối',
        requestedAction: 'VIEW',
        status: 'REJECTED',
        createdAt: '2026-11-25T00:00:00.000Z',
      },
    ];
    const newPending = {
      id: 'r-new-1',
      documentId: 'doc-10',
      documentTitle: 'Tài liệu mới xin',
      requestedAction: 'VIEW',
      status: 'PENDING',
      createdAt: '2026-11-26T00:00:00.000Z',
    };
    const onRejected = applyCreatedRequestToFilteredPage({
      currentRequests: rejectedList,
      currentTotal: 1,
      created: newPending,
      statusFilter: 'REJECTED',
      page: 1,
    });
    assert.equal(onRejected.nextRequests.length, 1);
    assert.equal(onRejected.nextRequests[0].id, 'r-rej-1');
    assert.equal(onRejected.nextTotal, 1);

    const onPending = applyCreatedRequestToFilteredPage({
      currentRequests: [],
      currentTotal: 0,
      created: newPending,
      statusFilter: 'PENDING',
      page: 1,
    });
    assert.equal(onPending.nextRequests.length, 1);
    assert.equal(onPending.nextTotal, 1);

    // Cancelling while in PENDING filter removes the row and decrements total
    const afterCancelPending = applyCancelledRequestToFilteredPage({
      currentRequests: onPending.nextRequests,
      currentTotal: onPending.nextTotal,
      requestId: 'r-new-1',
      statusFilter: 'PENDING',
    });
    assert.equal(afterCancelPending.nextRequests.length, 0);
    assert.equal(afterCancelPending.nextTotal, 0);

    // Cancelling while in ALL filter updates status to CANCELLED and keeps total intact
    const afterCancelAll = applyCancelledRequestToFilteredPage({
      currentRequests: [newPending],
      currentTotal: 5,
      requestId: 'r-new-1',
      statusFilter: 'ALL',
    });
    assert.equal(afterCancelAll.nextRequests[0].status, 'CANCELLED');
    assert.equal(afterCancelAll.nextTotal, 5);

    const readerCatalog = readWeb('app/reader/hooks/use-reader-catalog.ts');
    const catalogTab = readWeb('app/reader/tabs/catalog-tab.tsx');
    assert.doesNotMatch(readerCatalog, /pageSize=1000|pageSize=500|pageSize=100/);
    assert.match(readerCatalog, /READER_LOOKUP_PAGE_SIZE = 50/);
    assert.match(catalogTab, /staff-badge/);
    assert.match(catalogTab, /activeGrantsByDocId/);
    assert.match(catalogTab, /pendingRequestDocIds/);
  });

  it('[BUG-029] handles SSE session termination without extra /end POST, offers MFA CTA on page change errors, delays revokeObjectURL 15s, and tracks parallel downloadingDocIds', () => {
    const ownerDelivery = readWeb('app/owner/hooks/use-owner-delivery.ts');
    const readerViewer = readWeb('app/reader/hooks/use-reader-viewer.ts');
    const ownerHelpers = readWeb('app/owner/helpers.ts');

    assert.match(ownerDelivery, /subscribeRealtimeEvent[\s\S]*?'ACCESS_SESSION_UPDATED'/);
    const [, sseSection = ''] = ownerDelivery.split("'ACCESS_SESSION_UPDATED'");
    const [sseBody = ''] = sseSection.split('async function handleOpenPreview');
    assert.match(sseBody, /closePreviewLocally\(false\)/);
    assert.doesNotMatch(sseBody, /handleClosePreview\(/);

    for (const src of [ownerDelivery, readerViewer]) {
      const [, pageChangeFn = ''] = src.split('async function handlePageChange');
      assert.match(pageChangeFn, /shouldOfferMfaActionForError\(/);
      assert.match(pageChangeFn, /setMfaActionRequired\(true\)/);
    }

    assert.match(
      ownerHelpers,
      /setTimeout\(\(\)\s*=>\s*\{\s*window\.URL\.revokeObjectURL\(downloadUrl\);\s*\},\s*15_000\)/,
    );
    assert.match(
      ownerDelivery,
      /const \[downloadingDocIds, setDownloadingDocIds\] = useState<ReadonlySet<string>>/,
    );
  });
});
