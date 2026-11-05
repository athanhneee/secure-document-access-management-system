/**
 * Module: Bộ lọc Che dấu Dữ liệu Nhạy cảm trong Nhật ký (Sensitive Log Data Redaction)
 * Thuật toán: Duyệt cây theo chiều sâu giới hạn độ sâu (Depth-Bounded Recursive DFS Traversal)
 *   kết hợp chuẩn hóa khóa (Canonical Key Normalization) và đối sánh mẫu chuỗi con.
 * Mục đích: Ngăn chặn rò rỉ thông tin xác thực, khóa mật mã, phiên làm việc và nội dung tệp nhị phân
 *   ra luồng nhật ký hệ thống (log sink) mà không gây tràn ngăn xếp (stack overflow).
 */
export const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'password_hash',
  'newpassword',
  'currentpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'watermark_token',
  'watermarktoken',
  'secret',
  'jwt',
  'encryptionkey',
  'encryption_key',
  'encryption_key_ref',
  'dek',
  'kek',
  'key',
  'filecontent',
  'buffer',
  'content',
]);

/**
 * Thuật toán: Duyệt đệ quy DFS giới hạn độ sâu (Depth-Bounded DFS Object Graph Traversal)
 *   kết hợp chuẩn hóa khóa và đối sánh tập hợp O(1) / mẫu con.
 * Mục đích: Sao chép an toàn cấu trúc dữ liệu bất kỳ và thay thế toàn bộ giá trị nhạy cảm
 *   hoặc vùng nhớ đệm nhị phân bằng nhãn che dấu cố định trước khi tuần tự hóa JSON.
 * Cơ chế hoạt động:
 *   - Chốt chặn độ sâu (Depth / Cycle Guard): Dừng đệ quy ngay khi `depth > 10` hoặc gặp giá trị
 *     nguyên thủy/rỗng để bảo vệ ngăn xếp trước cấu trúc lồng sâu hoặc đồ thị có chu trình tham chiếu.
 *   - Xử lý phân nhánh kiểu dữ liệu: Duyệt ánh xạ từng phần tử với mảng (`depth + 1`), và thay thế
 *     ngay lập tức `Buffer` bằng chuỗi `[REDACTED_BUFFER]` để tránh ghi dữ liệu nhị phân thô.
 *   - Chuẩn hóa và nhận diện khóa nhạy cảm: Chuyển tên thuộc tính về chữ thường, loại bỏ dấu gạch ngang
 *     và gạch dưới (`[-_]`), sau đó tra cứu tập `SENSITIVE_KEYS` trong thời gian O(1) kết hợp kiểm tra
 *     chuỗi con đặc trưng để che dấu thành `[REDACTED]`.
 */
export function redactSensitiveData(data: unknown, depth = 0): unknown {
  // Thuật toán: Chốt chặn độ sâu đệ quy (Depth/Cycle Guard) và kiểm tra kiểu nguyên thủy
  if (depth > 10 || data === null || data === undefined) {
    return data;
  }

  if (typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => redactSensitiveData(item, depth + 1));
  }

  if (Buffer.isBuffer(data)) {
    return '[REDACTED_BUFFER]';
  }

  // Thuật toán: Chuẩn hóa khóa (Key Canonicalization) và đối sánh mẫu nhạy cảm trên từng thuộc tính
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase().replace(/[-_]/g, '');
    const isSensitive =
      SENSITIVE_KEYS.has(normalizedKey) ||
      SENSITIVE_KEYS.has(key.toLowerCase()) ||
      normalizedKey.includes('password') ||
      normalizedKey.includes('token') ||
      normalizedKey.includes('secret') ||
      normalizedKey.includes('encryptionkey');

    if (isSensitive) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactSensitiveData(value, depth + 1);
    } else {
      result[key] = value;
    }
  }

  return result;
}
