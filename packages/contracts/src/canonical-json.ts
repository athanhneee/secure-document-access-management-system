/**
 * @module CanonicalJson
 * Algorithm / Thuật toán: Chuẩn hóa JSON tất định theo RFC 8785 (JSON Canonicalization Scheme - JCS).
 * Mục đích: Đệ quy cấu trúc và sắp xếp khóa từ điển theo đơn vị mã UTF-16 để bảo đảm chuỗi đầu vào ký
 *   mật mã HMAC-SHA256 hoàn toàn tất định byte-for-byte giữa API, Worker và bộ kiểm định.
 * Quy tắc:
 *   1. Sắp xếp từ điển `Object.keys(obj).sort()` theo UTF-16 code units.
 *   2. Số hữu hạn chuẩn hóa qua `JSON.stringify`; `NaN`/`Infinity` quy về `'null'`; `bigint` chuyển sang chuỗi số.
 *   3. Lược bỏ khoảng trắng thừa; bỏ qua thuộc tính `undefined`, `symbol`, `function` trong object (trong mảng quy về `'null'`).
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  }

  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString());
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  if (Array.isArray(value)) {
    const serializedElements = value.map((element) =>
      typeof element === 'undefined' || typeof element === 'symbol' || typeof element === 'function'
        ? 'null'
        : canonicalizeJson(element),
    );
    return `[${serializedElements.join(',')}]`;
  }

  if (typeof value === 'object') {
    if (typeof (value as { toJSON?: () => unknown }).toJSON === 'function') {
      return canonicalizeJson((value as { toJSON: () => unknown }).toJSON());
    }

    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const val = obj[key];
      if (typeof val === 'undefined' || typeof val === 'symbol' || typeof val === 'function') {
        continue;
      }
      parts.push(`${JSON.stringify(key)}:${canonicalizeJson(val)}`);
    }
    return `{${parts.join(',')}}`;
  }

  return 'null';
}
