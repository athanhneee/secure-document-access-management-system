/**
 * Thuật toán: Tạo & Lưu Trữ Dấu Vân Tay Thiết Bị Ổn Định Không PII (`getOrCreateDeviceFingerprint`)
 * Mục đích:
 *   - Cung cấp định danh thiết bị ngẫu nhiên mật mã học ổn định trên mỗi hồ sơ trình duyệt (`dfp-<32 hex>`)
 *     để đính kèm vào `POST /documents/:id/sessions` và `GET /auth/session-posture`.
 *   - Cho phép cổng PEP nhận diện thiết bị đã từng mở phiên hợp lệ (`deviceTrust: true`) thay vì luôn bị cộng
 *     cố định `+15` điểm rủi ro `UNTRUSTED_DEVICE` do thiếu `deviceFingerprint`, mà vẫn giữ nguyên mô hình Zero Trust
 *     (trình duyệt/thiết bị mới hoàn toàn vẫn bị đánh dấu chưa tin cậy ở lần truy cập đầu tiên).
 */

const DEVICE_FINGERPRINT_STORAGE_KEY = 'sda_device_fingerprint_v1';
const DEVICE_FINGERPRINT_RE = /^dfp-[0-9a-f]{32,64}$/i;

let memoryFallbackFingerprint: string | null = null;

function generateCryptoDeviceFingerprint(): string | null {
  const cryptoObj = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    cryptoObj.getRandomValues(bytes);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `dfp-${hex}`;
  }
  if (cryptoObj && typeof cryptoObj.randomUUID === 'function') {
    return `dfp-${cryptoObj.randomUUID().replace(/-/g, '')}`;
  }
  return null;
}

export function isValidDeviceFingerprint(value: unknown): value is string {
  return typeof value === 'string' && DEVICE_FINGERPRINT_RE.test(value.trim());
}

/**
 * Thuật toán: Truy Xuất Hoặc Khởi Tạo Dấu Vân Tay Thiết Bị An Toàn Cho SSR & Private Mode (`getOrCreateDeviceFingerprint`)
 */
export function getOrCreateDeviceFingerprint(): string | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }

  try {
    const existing = window.localStorage.getItem(DEVICE_FINGERPRINT_STORAGE_KEY);
    if (isValidDeviceFingerprint(existing)) {
      const normalized = existing.trim().toLowerCase();
      memoryFallbackFingerprint = normalized;
      return normalized;
    }
  } catch {
    // Trình duyệt chặn localStorage (chế độ riêng tư nghiêm ngặt): rơi về bộ nhớ phiên hiện tại
  }

  if (memoryFallbackFingerprint && isValidDeviceFingerprint(memoryFallbackFingerprint)) {
    return memoryFallbackFingerprint;
  }

  const created = generateCryptoDeviceFingerprint();
  if (!created) {
    return undefined;
  }

  memoryFallbackFingerprint = created;
  try {
    window.localStorage.setItem(DEVICE_FINGERPRINT_STORAGE_KEY, created);
  } catch {
    // Bỏ qua an toàn nếu bộ nhớ cục bộ chỉ đọc
  }
  return created;
}
