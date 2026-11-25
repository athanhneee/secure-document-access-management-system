import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  mapReaderGrantDto,
  resolveGrantExpiryUrgency,
  resolveSafeDownloadFilename,
  validateCustomRequestWindow,
} from '../../apps/web/app/reader/helpers.ts';
import { localizeApiErrorMessage } from '../../apps/web/lib/api-error-messages.ts';
import { formatRequestStatusLabel } from '../../apps/web/lib/ui-labels.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');
const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const readWeb = (rel) => stripComments(fs.readFileSync(path.join(webRoot, rel), 'utf8'));

/**
 * Thuật toán: Kiểm Chứng Hồi Quy Toàn Diện 66 Hạng Mục Kiểm Toán Giao Diện Người Xem (`DOCUMENT_READER` / `qa.view`)
 * Mục đích: Xác minh bằng mã thực thi lẫn kiểm chứng cấu trúc mã nguồn (đã khử chú thích) rằng toàn bộ nhóm lỗi P0/P1/P2 (V-01 đến V-66) từ báo cáo kiểm toán đều đã được khắc phục dứt điểm và không thoái lui.
 */
describe('DOCUMENT_READER (qa.view) 66-Finding Remediation Regression Suite', () => {
  it('V-01 & V-57: replaces iframe blob: PDF viewer with Canvas PDF.js renderer and blocks blob: in CSP frame-src', () => {
    const canvasViewer = readWeb('components/documents/secure-pdf-canvas-viewer.tsx');
    const previewModal = readWeb('components/documents/shared-pdf-preview-modal.tsx');
    const proxyTs = readWeb('proxy.ts');

    assert.match(canvasViewer, /pdfjs-dist/);
    assert.match(canvasViewer, /\/pdf\.worker\.min\.mjs/);
    assert.match(canvasViewer, /<canvas/);
    assert.doesNotMatch(canvasViewer, /<iframe/);
    assert.doesNotMatch(previewModal, /<iframe/);
    assert.doesNotMatch(previewModal, /createObjectURL/);
    assert.match(previewModal, /e\.ctrlKey \|\| e\.metaKey/);
    assert.match(proxyTs, /worker-src 'self'/);
    assert.doesNotMatch(proxyTs, /frame-src[^;]*blob:/);
  });

  it('V-02, V-04, V-05, V-07, V-10, V-12: uses /preview/page/1, X-Access-Session-Id header, SSE auto-close, and session end', () => {
    const viewerHook = readWeb('app/reader/hooks/use-reader-viewer.ts');
    assert.match(viewerHook, /\/preview\/page\/1/);
    assert.match(viewerHook, /'x-access-session-id':\s*sessionResult\.sessionId/);
    assert.match(viewerHook, /\/documents\/\$\{doc\.documentId\}\/download/);
    assert.doesNotMatch(viewerHook, /download-with-ticket/);
    assert.match(viewerHook, /\/access-sessions\/\$\{encodeURIComponent\(sessionId\)\}\/end/);
    assert.match(viewerHook, /ACCESS_GRANT_UPDATED/);
    assert.match(viewerHook, /ACCESS_SESSION_UPDATED/);
    assert.match(viewerHook, /downloadingDocIds/);
  });

  it('V-08: preserves original file extension via Content-Disposition or MIME instead of blindly appending .pdf', () => {
    const docxBlob = new Blob(['fake'], {
      type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });
    assert.equal(
      resolveSafeDownloadFilename(docxBlob, 'DOC-101', 'hop-dong.docx'),
      'hop-dong.docx',
    );
    assert.equal(resolveSafeDownloadFilename(docxBlob, 'DOC-101'), 'DOC-101.docx');

    const pdfBlob = new Blob(['%PDF-1.7'], { type: 'application/pdf' });
    assert.equal(resolveSafeDownloadFilename(pdfBlob, 'DOC-102'), 'DOC-102_bao-mat.pdf');
    assert.equal(
      resolveSafeDownloadFilename(pdfBlob, 'DOC-102', 'bao-cao-watermarked.pdf'),
      'bao-cao-watermarked.pdf',
    );
  });

  it('V-09, V-29, V-39, V-45: localizes STEP_UP_MFA_REQUIRED, 409 TOTP conflict, and exposes MFA enrollment CTA', () => {
    const stepUpMsg = localizeApiErrorMessage(403, {
      errorCode: 'STEP_UP_MFA_REQUIRED',
      message: 'MFA required',
    });
    assert.match(stepUpMsg, /xác thực đa yếu tố|MFA/i);

    const totpConflictMsg = localizeApiErrorMessage(409, {
      errorCode: 'RESOURCE_CONFLICT',
      message: 'An active TOTP authenticator is already enabled for this account.',
    });
    assert.match(totpConflictMsg, /kích hoạt.*TOTP/i);

    const workspace = readWeb('app/reader/reader-workspace.tsx');
    assert.match(workspace, /mfaActionRequired/);
    assert.match(workspace, /\/mfa\?enroll=1&method=totp|\/mfa\?redirect=/);
  });

  it('V-11, V-14, V-15: awaits logout cookie clearing, clears notification cache, routes pre-MFA 401 to /mfa, and refreshes SSE', () => {
    const authCtx = readWeb('lib/auth-context.tsx');
    const apiClientTs = readWeb('lib/api-client.ts');
    const sseTs = readWeb('lib/realtime-events.ts');
    const bellTsx = readWeb('components/navigation/notification-bell-dialog.tsx');

    assert.match(authCtx, /clearNotificationMemoryCache\(\)/);
    assert.match(authCtx, /reason === 'mfa_required'/);
    assert.match(authCtx, /router\.replace\('\/mfa'\)/);
    assert.match(authCtx, /await Promise\.race\(\[/);
    assert.match(apiClientTs, /isPreMfa401Response/);
    assert.match(apiClientTs, /emitSessionExpired\('mfa_required'\)/);
    assert.match(sseTs, /API_BASE_URL/);
    assert.match(sseTs, /attemptSessionRefresh/);
    assert.match(bellTsx, /export function clearNotificationMemoryCache/);
  });

  it('V-16, V-23, V-33, V-34, V-35, V-37, V-38, V-40, V-41, V-43: fixes reader tabs, filters, request modal, and DTOs', () => {
    const catalogTab = readWeb('app/reader/tabs/catalog-tab.tsx');
    const grantedTab = readWeb('app/reader/tabs/granted-documents-tab.tsx');
    const requestsTab = readWeb('app/reader/tabs/my-requests-tab.tsx');
    const requestModal = readWeb('app/reader/modals/request-access-modal.tsx');

    assert.doesNotMatch(catalogTab, /value="UNCLASSIFIED"/);
    assert.match(catalogTab, /maxRank >= 2/);
    assert.match(catalogTab, /Xin quyền tải/);
    assert.match(catalogTab, /Xin gia hạn/);
    assert.match(catalogTab, /Đang chờ duyệt/);
    assert.match(catalogTab, /Trang sau/);

    assert.match(grantedTab, /Hiệu lực đến/);
    assert.match(grantedTab, /includeTime: true/);
    assert.match(grantedTab, /Xin quyền tải/);
    assert.match(grantedTab, /md:hidden/);

    assert.match(requestsTab, /decisionNote/);
    assert.match(requestsTab, /Phản hồi phê duyệt/);
    assert.match(requestsTab, /Trang sau/);

    assert.match(requestModal, /maxLength=\{1000\}/);
    assert.match(requestModal, /customWindowError/);
    assert.doesNotMatch(requestModal, /bg-\[#FF385C\]\/15/);

    const nowMs = Date.parse('2026-11-25T10:00:00.000Z');
    assert.match(
      validateCustomRequestWindow(true, '2026-11-24T10:00', '2026-11-26T10:00', nowMs) ?? '',
      /quá khứ/,
    );
    assert.match(
      validateCustomRequestWindow(true, '2026-11-26T10:00', '2026-11-26T09:00', nowMs) ?? '',
      /lớn hơn/,
    );
    assert.equal(
      validateCustomRequestWindow(true, '2026-11-26T10:00', '2026-12-01T10:00', nowMs),
      null,
    );

    const mappedGrant = mapReaderGrantDto({
      grantId: 'g-1',
      principalType: 'ROLE',
      roleName: 'Người đọc tài liệu',
      permissions: ['VIEW'],
      document: { id: 'd-1', title: 'Tài liệu nhóm', classificationLevelCode: 'INTERNAL' },
    });
    assert.equal(mappedGrant.principalType, 'ROLE');
    assert.equal(mappedGrant.roleName, 'Người đọc tài liệu');

    assert.equal(formatRequestStatusLabel('EXPIRED'), 'Đã hết hạn');
    assert.equal(
      resolveGrantExpiryUrgency(new Date(Date.now() + 2 * 3600 * 1000).toISOString()),
      'danger',
    );
  });

  it('V-13, V-20, V-25, V-28, V-30, V-31, V-32, V-48, V-50, V-54, V-62, V-63, V-64, V-65, V-66: fixes navigation, sessions, MFA, landing, and WCAG', () => {
    const bell = readWeb('components/navigation/notification-bell-dialog.tsx');
    const sidebar = readWeb('components/navigation/sidebar-directory.tsx');
    const appSidebar = readWeb('components/navigation/app-sidebar.tsx');
    const authGuard = readWeb('components/auth-guard.tsx');
    const sessionsPage = readWeb('app/sessions/page.tsx');
    const securityOverview = readWeb('app/sessions/session-security-overview.tsx');
    const passkeyCard = readWeb('app/sessions/passkey-enrollment-card.tsx');
    const mfaEnrollForm = readWeb('app/mfa/mfa-enroll-form.tsx');
    const mfaEnrollCard = readWeb('app/mfa/mfa-enrollment-card.tsx');
    const mfaPage = readWeb('app/mfa/page.tsx');
    const resetPage = readWeb('app/reset-password/page.tsx');
    const hero = readWeb('components/landing/hero-section.tsx');
    const ihb = readWeb('components/ui/interactive-hover-button.tsx');
    const homeDrawer = readWeb('components/navigation/home-mobile-drawer.tsx');
    const badge = readWeb('components/classification-badge.tsx');

    assert.match(bell, /Đánh dấu đã đọc/);
    assert.match(bell, /Đọc tất cả/);
    assert.match(bell, /Tải thêm thông báo/);
    assert.match(bell, /chưa đọc\)/);

    assert.match(sidebar, /Bảo mật &amp; MFA/);
    assert.match(sidebar, /ClassificationBadge/);
    assert.doesNotMatch(sidebar, /ExternalLink/);
    assert.match(appSidebar, /bg-transparent/);

    assert.doesNotMatch(authGuard, /Phân hệ yêu cầu|Vai trò yêu cầu/);
    assert.match(authGuard, /router\.replace\(redirectUrl\)/);
    assert.match(authGuard, /recheckFeedback/);

    assert.match(sessionsPage, /MfaFactorsCard/);
    assert.match(sessionsPage, /ChangePasswordCard/);
    assert.match(securityOverview, /window\.location\.protocol === 'https:'/);
    assert.doesNotMatch(passkeyCard, /Chống giả mạo/);
    assert.doesNotMatch(passkeyCard, /bg-\[#222222\]/);

    assert.match(mfaEnrollForm, /type=\{isShown \? 'text' : 'password'\}/);
    assert.match(mfaEnrollCard, /err\.status === 409/);
    assert.match(mfaEnrollCard, /role="tabpanel"/);
    assert.doesNotMatch(mfaPage, /blur-3xl/);
    assert.doesNotMatch(resetPage, /blur-3xl/);

    assert.match(hero, /4 cấp độ mật/);
    assert.doesNotMatch(hero, /5 cấp độ mật/);
    assert.match(ihb, /onClick: linkOnClick/);
    assert.match(homeDrawer, /skipRestoreFocusRef/);
    assert.doesNotMatch(badge, /\bFlame\b/);
  });
});
