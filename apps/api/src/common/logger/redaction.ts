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
 *   kết hợp tập tổ tiên chống chu trình (`Ancestor WeakSet Cycle Guard`), chuẩn hóa `BigInt` sang chuỗi thập phân
 *   và đối sánh khóa nhạy cảm `O(1)`.
 * Mục đích: Sao chép an toàn cấu trúc dữ liệu bất kỳ, thay thế giá trị nhạy cảm hoặc vùng đệm vượt quá độ sâu `10`
 *   bằng nhãn che dấu cố định trước khi tuần tự hóa JSON mà không làm hỏng nhánh DAG dùng chung hợp lệ.
 */
export function redactSensitiveData(
  data: unknown,
  depth = 0,
  seen: WeakSet<object> = new WeakSet<object>(),
): unknown {
  if (depth > 10) {
    return '[MAX_DEPTH_REDACTED]';
  }

  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'bigint') {
    return data.toString();
  }

  if (typeof data !== 'object') {
    return data;
  }

  if (Buffer.isBuffer(data)) {
    return '[REDACTED_BUFFER]';
  }

  if (data instanceof Date) {
    return data.toISOString();
  }

  if (seen.has(data)) {
    return '[CIRCULAR]';
  }

  seen.add(data);
  try {
    if (Array.isArray(data)) {
      return data.map((item) =>
        typeof item === 'bigint'
          ? item.toString()
          : typeof item === 'object' && item !== null
            ? redactSensitiveData(item, depth + 1, seen)
            : item,
      );
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
      } else if (typeof value === 'bigint') {
        result[key] = value.toString();
      } else if (typeof value === 'object' && value !== null) {
        result[key] = redactSensitiveData(value, depth + 1, seen);
      } else {
        result[key] = value;
      }
    }

    return result;
  } finally {
    seen.delete(data);
  }
}
