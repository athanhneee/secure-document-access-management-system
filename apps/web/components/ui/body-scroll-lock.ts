/**
 * Thuật toán: Khóa Cuộn Nền Tham Chiếm Có Đếm Tham Chiếu & Chống Gọi Kép StrictMode (`lockBodyScroll`)
 * Mục đích:
 *   - Duy trì bộ đếm `activeLocks` toàn cục cho mọi `<dialog>.showModal()` đang mở (`Dialog`, `ConfirmDialog` lồng nhau, `AppSidebar`, `HomeMobileDrawer`).
 *   - Đảm bảo đóng hộp thoại con (`ConfirmDialog`) không bao giờ gỡ `document.body.style.overflow = 'hidden'` khi hộp thoại cha vẫn đang mở.
 *   - Bảo vệ hàm `unlock()` bằng cờ đơn điệu `let released = false` để an toàn tuyệt đối trước chu kỳ dọn dẹp kép của React StrictMode.
 */
let activeLocks = 0;
let savedBodyOverflow = '';

export function lockBodyScroll(): () => void {
  if (typeof document === 'undefined') {
    return () => {};
  }

  if (activeLocks === 0) {
    savedBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
  }
  activeLocks += 1;

  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeLocks = Math.max(0, activeLocks - 1);
    if (activeLocks === 0 && typeof document !== 'undefined') {
      document.body.style.overflow = savedBodyOverflow;
      savedBodyOverflow = '';
    }
  };
}

export function getActiveBodyScrollLocks(): number {
  return activeLocks;
}
