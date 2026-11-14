/**
 * Thuật toán: Truy Vấn Phần Tử Tương Tác Khả Dụng Phục Vụ Bẫy Tiêu Điểm Bàn Phím (`getVisibleFocusables`)
 * Mục đích: Lọc danh sách các điều khiển có thể nhận focus thực tế bên trong `<dialog>` theo chuẩn WAI-ARIA 1.2 (`O(K)` với `K` là số phần tử con).
 */
export const DIALOG_FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export function getVisibleFocusables(dialogEl: HTMLElement): HTMLElement[] {
  return Array.from(dialogEl.querySelectorAll<HTMLElement>(DIALOG_FOCUSABLE_SELECTOR)).filter(
    (el) =>
      !el.hasAttribute('disabled') &&
      el.getAttribute('aria-hidden') !== 'true' &&
      window.getComputedStyle(el).display !== 'none' &&
      window.getComputedStyle(el).visibility !== 'hidden',
  );
}
