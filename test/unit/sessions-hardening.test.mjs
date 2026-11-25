import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  formatSessionTimestamp,
  summarizeUserAgent,
} from '../../apps/web/app/sessions/session-device.helper.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

/**
 * Thuật toán: Kiểm Chứng Bộ Phân Tích User-Agent Đa Nền Tảng, Trạng Thái Lỗi/Xác Nhận `/sessions` & Cấu Hình Proxy Production
 * Mục đích: Khóa chặn hồi quy lỗi iPhone/iPad bị nhận thành `macOS`, lỗi nuốt ngoại lệ mạng trên `/sessions`,
 * thiếu vô hiệu hóa nút khi chỉ có 1 thiết bị, thiếu `ConfirmDialog` khi thu hồi từng phiên và thiếu cấu hình IP/proxy trong `proxy.ts` / `compose.prod.yaml`.
 */
describe('Sessions User-Agent Summarizer (iOS/iPadOS/Android/Desktop Accuracy)', () => {
  it('detects iPhone and iPad as iOS/iPadOS instead of macOS despite "like Mac OS X"', () => {
    const iphoneSafari = summarizeUserAgent(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    );
    assert.equal(iphoneSafari.os, 'iOS');
    assert.equal(iphoneSafari.browser, 'Apple Safari');
    assert.equal(iphoneSafari.label, 'Apple Safari · iOS');
    assert.equal(iphoneSafari.isMobile, true);

    const ipadSafari = summarizeUserAgent(
      'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    );
    assert.equal(ipadSafari.os, 'iPadOS');
    assert.equal(ipadSafari.browser, 'Apple Safari');
    assert.equal(ipadSafari.label, 'Apple Safari · iPadOS');
    assert.equal(ipadSafari.isMobile, true);
  });

  it('distinguishes iOS browsers (CriOS, FxiOS, EdgiOS), Opera (OPR), Samsung Internet, and desktop OSes', () => {
    const chromeIos = summarizeUserAgent(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1',
    );
    assert.equal(chromeIos.label, 'Google Chrome · iOS');
    assert.equal(chromeIos.isMobile, true);

    const firefoxIos = summarizeUserAgent(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15',
    );
    assert.equal(firefoxIos.label, 'Mozilla Firefox · iOS');

    const edgeIos = summarizeUserAgent(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/130.0 Mobile/15E148 Safari/605.1.15',
    );
    assert.equal(edgeIos.label, 'Microsoft Edge · iOS');

    const operaWin = summarizeUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/114.0.0.0',
    );
    assert.equal(operaWin.label, 'Opera · Windows');
    assert.equal(operaWin.isMobile, false);

    const samsungAndroid = summarizeUserAgent(
      'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
    );
    assert.equal(samsungAndroid.label, 'Samsung Internet · Android');
    assert.equal(samsungAndroid.isMobile, true);

    const macSafari = summarizeUserAgent(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    );
    assert.equal(macSafari.label, 'Apple Safari · macOS');
    assert.equal(macSafari.isMobile, false);

    const fallback = summarizeUserAgent(null);
    assert.equal(fallback.label, 'Thiết bị trình duyệt web');
    assert.equal(fallback.isMobile, false);
    assert.equal(formatSessionTimestamp(null), '—');
    assert.equal(formatSessionTimestamp('not-a-date'), '—');
  });
});

describe('Sessions Page UX Safety & Production Proxy/Docker Contracts', () => {
  it('enforces error surfacing, disabled bulk revoke when 0 remote sessions, and ConfirmDialog for single revoke', () => {
    const pageTsx = fs.readFileSync(path.join(repoRoot, 'apps/web/app/sessions/page.tsx'), 'utf8');
    const listTsx = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/sessions/active-sessions-list.tsx'),
      'utf8',
    );

    assert.match(pageTsx, /fetchError/);
    assert.match(pageTsx, /setFetchError\(/);
    assert.match(
      pageTsx,
      /disabled=\{isRevokingOthers \|\| isFetching \|\| otherSessionsCount === 0\}/,
    );
    assert.match(pageTsx, /confirmRevokeTarget/);
    assert.match(pageTsx, /title="Thu hồi phiên thiết bị từ xa"/);
    assert.match(listTsx, /fetchError && sessions\.length === 0/);
    assert.match(listTsx, /Thử tải lại/);
  });

  it('forwards real client IP headers in proxy.ts and wires INTERNAL_API_ORIGIN + TRUST_PROXY in compose.prod.yaml', () => {
    const proxyTs = fs.readFileSync(path.join(repoRoot, 'apps/web/proxy.ts'), 'utf8');
    const composeProd = fs.readFileSync(path.join(repoRoot, 'infra/compose.prod.yaml'), 'utf8');

    assert.match(proxyTs, /buildApiProxyHeaders/);
    assert.match(proxyTs, /x-forwarded-for/);
    assert.match(proxyTs, /x-forwarded-proto/);
    assert.match(composeProd, /TRUST_PROXY:\s*\$\{TRUST_PROXY:-loopback,uniquelocal\}/);
    assert.match(
      composeProd,
      /INTERNAL_API_ORIGIN:\s*\$\{INTERNAL_API_ORIGIN:-http:\/\/api:3001\}/,
    );
    assert.match(composeProd, /AUTH_SESSION_IDLE_TTL_SECONDS/);
    assert.match(composeProd, /AUTH_SESSION_RETENTION_DAYS/);
  });
});
