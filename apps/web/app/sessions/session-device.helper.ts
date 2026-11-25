/**
 * Thuật toán: Phân Tích Chuỗi User-Agent Định Danh Trình Duyệt & Hệ Điều Hành (`summarizeUserAgent`)
 * Mục đích:
 *   - Ưu tiên nhận diện `iPadOS` / `iOS` và `Android` TRƯỚC `macOS` / `Linux` để tránh lỗi chuỗi `like Mac OS X`
 *     trên iPhone/iPad bị nhận nhầm thành `macOS`, hoặc `Linux; Android` bị nhận nhầm thành `Linux`.
 *   - Ưu tiên nhận diện các trình duyệt phái sinh/di động (`Edg/`, `EdgiOS/`, `EdgA/`, `OPR/`, `SamsungBrowser/`,
 *     `CriOS/`, `FxiOS/`) TRƯỚC `Chrome/` và `Safari/` để không gán nhầm nhãn trình duyệt.
 */

export interface DeviceSummary {
  label: string;
  browser: string;
  os: string;
  isMobile: boolean;
}

export function summarizeUserAgent(ua: string | null | undefined): DeviceSummary {
  if (!ua || !ua.trim()) {
    return {
      label: 'Thiết bị trình duyệt web',
      browser: 'Trình duyệt Web',
      os: 'Hệ điều hành khác',
      isMobile: false,
    };
  }

  const normalized = ua.toLowerCase();

  // Thứ tự OS: iPadOS/iOS trước macOS (vì UA iOS chứa "like Mac OS X"); Android trước Linux (vì UA Android chứa "Linux").
  const os = normalized.includes('ipad')
    ? 'iPadOS'
    : normalized.includes('iphone') || normalized.includes('ipod')
      ? 'iOS'
      : normalized.includes('android')
        ? 'Android'
        : normalized.includes('windows')
          ? 'Windows'
          : normalized.includes('cros')
            ? 'ChromeOS'
            : normalized.includes('mac os') || normalized.includes('macintosh')
              ? 'macOS'
              : normalized.includes('linux') || normalized.includes('x11')
                ? 'Linux'
                : 'Hệ điều hành khác';

  // Thứ tự Browser: Edge/Opera/Samsung/Brave/Vivaldi/iOS-browsers trước Chrome và Safari.
  const browser =
    normalized.includes('edg/') ||
    normalized.includes('edgios/') ||
    normalized.includes('edga/') ||
    normalized.includes('edge/')
      ? 'Microsoft Edge'
      : normalized.includes('opr/') || normalized.includes('opera')
        ? 'Opera'
        : normalized.includes('samsungbrowser/')
          ? 'Samsung Internet'
          : normalized.includes('brave')
            ? 'Brave'
            : normalized.includes('vivaldi/')
              ? 'Vivaldi'
              : normalized.includes('crios/')
                ? 'Google Chrome'
                : normalized.includes('fxios/')
                  ? 'Mozilla Firefox'
                  : normalized.includes('chrome/') || normalized.includes('chromium/')
                    ? 'Google Chrome'
                    : normalized.includes('firefox/')
                      ? 'Mozilla Firefox'
                      : normalized.includes('safari/')
                        ? 'Apple Safari'
                        : 'Trình duyệt Web';

  const isMobile =
    os === 'iOS' || os === 'iPadOS' || os === 'Android' || /mobile|tablet/u.test(normalized);

  return {
    label: `${browser} · ${os}`,
    browser,
    os,
    isMobile,
  };
}

/**
 * Thuật toán: Định Dạng Dấu Thời Gian Phiên Theo Múi Giờ Việt Nam (`formatSessionTimestamp`)
 */
export function formatSessionTimestamp(iso?: string | null): string {
  if (!iso) return '—';
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return '—';
  return parsed.toLocaleString('vi-VN');
}
