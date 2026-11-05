/**
 * @module PolicyCompilerParsers
 * Algorithm: Structural AST Value, Operator & Obligation Bounds Parsers for ABAC Compiler.
 * Phân tích cú pháp toán tử, giá trị kỳ vọng JSON và nghĩa vụ bảo mật cho trình biên dịch ABAC.
 */
import {
  MAX_SESSION_MINUTES_CEILING,
  MAX_SESSION_MINUTES_FLOOR,
  POLICY_OPERATORS,
  VALID_SIMPLE_OBLIGATION_TYPES,
} from './abac.types.js';
import type { ExpectedValue, PolicyObligation, PolicyOperator, TimeWindow } from './abac.types.js';

export class PolicyCompilationError extends Error {
  constructor(readonly issueCodes: string[]) {
    super('Policy validation failed.');
    this.name = 'PolicyCompilationError';
  }
}

/**
 * Algorithm / Thuật toán: Xác thực toán tử thuộc tập từ vựng cho phép `POLICY_OPERATORS`.
 */
export function parseOperator(value: string): PolicyOperator {
  if (!POLICY_OPERATORS.includes(value as PolicyOperator)) {
    throw new PolicyCompilationError(['UNSUPPORTED_OPERATOR']);
  }
  return value as PolicyOperator;
}

/**
 * Algorithm / Thuật toán: Phân tích cú pháp và thu hẹp kiểu giá trị kỳ vọng JSON (`ExpectedValue` Structural Parsing).
 * Chấp nhận kiểu vô hướng nguyên thủy, mảng đồng nhất nguyên thủy hoặc đối tượng `TimeWindow`
 * đủ 3 trường `{ start, end, timeZone }`; từ chối mọi cấu trúc JSON bất thường khác.
 */
export function parseExpected(value: unknown): ExpectedValue {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (
    Array.isArray(value) &&
    value.every((item) => ['string', 'number', 'boolean'].includes(typeof item))
  ) {
    return value as Array<string | number | boolean>;
  }
  if (isRecord(value)) {
    const start = value['start'];
    const end = value['end'];
    const timeZone = value['timeZone'];
    if (typeof start === 'string' && typeof end === 'string' && typeof timeZone === 'string') {
      return { start, end, timeZone } satisfies TimeWindow;
    }
  }
  throw new PolicyCompilationError(['INVALID_EXPECTED_VALUE']);
}

/**
 * Algorithm / Thuật toán: Phân tích và kiểm tra biên tham số của mảng nghĩa vụ bảo mật (`PolicyObligation` Bounds Parsing).
 * Chuẩn hóa cả dạng chuỗi rút gọn lẫn đối tượng có tham số, cưỡng chế `MAX_SESSION_MINUTES`
 * phải là số nguyên nằm trong đoạn `[MAX_SESSION_MINUTES_FLOOR, MAX_SESSION_MINUTES_CEILING]`.
 */
export function parseObligations(value: unknown): PolicyObligation[] {
  if (!Array.isArray(value)) throw new PolicyCompilationError(['INVALID_OBLIGATION']);
  return value.map((item) => {
    if (typeof item === 'string') {
      if (!(VALID_SIMPLE_OBLIGATION_TYPES as readonly string[]).includes(item)) {
        throw new PolicyCompilationError(['INVALID_OBLIGATION']);
      }
      return { type: item } as PolicyObligation;
    }
    if (isRecord(item) && typeof item['type'] === 'string') {
      if (item['type'] === 'MAX_SESSION_MINUTES') {
        if (
          typeof item['minutes'] !== 'number' ||
          !Number.isInteger(item['minutes']) ||
          item['minutes'] < MAX_SESSION_MINUTES_FLOOR ||
          item['minutes'] > MAX_SESSION_MINUTES_CEILING
        ) {
          throw new PolicyCompilationError(['INVALID_OBLIGATION']);
        }
        return { type: 'MAX_SESSION_MINUTES', minutes: item['minutes'] };
      }
      if ((VALID_SIMPLE_OBLIGATION_TYPES as readonly string[]).includes(item['type'])) {
        return { type: item['type'] } as PolicyObligation;
      }
    }
    throw new PolicyCompilationError(['INVALID_OBLIGATION']);
  });
}

/**
 * Algorithm / Thuật toán: Kiểm tra thu hẹp kiểu đối tượng bản ghi thuần túy (Plain Object Type Guard).
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Algorithm / Thuật toán: Khử trùng lặp bằng Set và sắp xếp thứ tự từ điển tất định.
 */
export function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

/**
 * Algorithm / Thuật toán: So sánh thứ tự hai định danh số nguyên lớn 64-bit lưu dưới dạng chuỗi.
 */
export function compareBigIntStrings(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}
