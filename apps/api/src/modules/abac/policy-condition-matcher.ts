/**
 * @module PolicyConditionMatcher
 * Algorithm: Deterministic ABAC Atomic Predicate & Multi-Valued Set Condition Matcher.
 * Trải phẳng ngữ cảnh 3 miền (subject, resource, environment) và đối chiếu vị từ điều kiện đơn nguyên.
 */
import type {
  ExpectedValue,
  PolicyCondition,
  PolicyEvaluationInput,
  TimeWindow,
} from './abac.types.js';
import { cidrMatch } from './cidr.js';

export type RuntimeValue = string | number | boolean | string[] | null | undefined;

/**
 * Algorithm / Thuật toán: Trải phẳng cây ngữ cảnh phân cấp (Hierarchical Context Flattening).
 * Mục đích: Ánh xạ cấu trúc 3 miền (subject, resource, environment) thành bảng băm khóa phẳng O(1) khi tra cứu.
 */
export function flattenContext(
  input: PolicyEvaluationInput,
): Readonly<Record<string, RuntimeValue>> {
  return {
    'subject.clearanceRank': input.subject.clearanceRank,
    'subject.departmentId': input.subject.departmentId,
    'subject.employmentStatus': input.subject.employmentStatus,
    'subject.projects': input.subject.projects,
    'resource.classificationRank': input.resource.classificationRank,
    'resource.ownerId': input.resource.ownerId,
    'resource.departmentId': input.resource.departmentId,
    'resource.category': input.resource.category,
    'resource.status': input.resource.status,
    'environment.currentTime': input.environment.currentTime,
    'environment.ip': input.environment.ip,
    'environment.trustedNetwork': input.environment.trustedNetwork,
    'environment.deviceTrust': input.environment.deviceTrust,
    'environment.mfa': input.environment.mfa,
    'environment.riskScore': input.environment.riskScore,
  };
}

/**
 * Algorithm / Thuật toán: Kiểm tra thiếu vắng thuộc tính (Null/Empty-Set Absence Check).
 */
export function isMissingAttribute(value: RuntimeValue): boolean {
  return value === null || value === undefined || (Array.isArray(value) && value.length === 0);
}

/**
 * Algorithm / Thuật toán: Đối chiếu vị từ điều kiện đơn nguyên (Atomic Predicate Matching).
 * Mục đích: Kiểm tra giá trị thực tế của thuộc tính với toán tử chính sách (EQ, NEQ, IN, NOT_IN,
 * GTE, LTE, BETWEEN, CIDR_MATCH, TIME_BETWEEN, EXISTS), tự động phân nhánh cho mảng đa trị.
 */
export function matchesCondition(
  condition: PolicyCondition,
  attributes: Readonly<Record<string, RuntimeValue>>,
): boolean {
  const actual = attributes[condition.attribute];
  const exists = !isMissingAttribute(actual);
  if (condition.operator === 'EXISTS') return exists === condition.expected;
  if (!exists) return false;
  if (Array.isArray(actual)) return matchArray(condition, actual);
  switch (condition.operator) {
    case 'EQ':
      return equal(actual, condition.expected);
    case 'NEQ':
      return !equal(actual, condition.expected);
    case 'IN':
      return (
        Array.isArray(condition.expected) && condition.expected.some((item) => equal(actual, item))
      );
    case 'NOT_IN':
      return (
        Array.isArray(condition.expected) &&
        condition.expected.every((item) => !equal(actual, item))
      );
    case 'GTE':
      return compare(actual, condition.expected) >= 0;
    case 'LTE':
      return compare(actual, condition.expected) <= 0;
    case 'BETWEEN':
      return (
        Array.isArray(condition.expected) &&
        compare(actual, condition.expected[0]!) >= 0 &&
        compare(actual, condition.expected[1]!) <= 0
      );
    case 'CIDR_MATCH':
      return typeof actual === 'string' && cidrMatchesAny(actual, condition.expected);
    case 'TIME_BETWEEN':
      return typeof actual === 'string' && timeBetween(actual, condition.expected as TimeWindow);
    default:
      return false;
  }
}

/**
 * Algorithm / Thuật toán: Đối chiếu tập hợp cho thuộc tính mảng đa trị (Set-Membership & Disjointness Matching).
 *   - EQ / IN: kiểm tra giao khác rỗng (tồn tại phần tử chung giữa tập thực tế và kỳ vọng).
 *   - NEQ / NOT_IN: kiểm tra hai tập rời nhau hoàn toàn (mọi phần tử thực tế đều khác tập cấm).
 */
function matchArray(condition: PolicyCondition, actual: string[]): boolean {
  if (condition.operator === 'EQ') return actual.some((item) => equal(item, condition.expected));
  if (condition.operator === 'NEQ') return actual.every((item) => !equal(item, condition.expected));
  const expected = condition.expected;
  if (condition.operator === 'IN' && Array.isArray(expected)) {
    return actual.some((item) => expected.some((candidate) => equal(item, candidate)));
  }
  if (condition.operator === 'NOT_IN' && Array.isArray(expected)) {
    return actual.every((item) => expected.every((candidate) => !equal(item, candidate)));
  }
  return false;
}

/**
 * Algorithm / Thuật toán: So sánh bằng nghiêm ngặt kiểu nguyên thủy (Strict Scalar Equality).
 */
function equal(actual: RuntimeValue, expected: ExpectedValue): boolean {
  return (
    (typeof actual === 'string' || typeof actual === 'number' || typeof actual === 'boolean') &&
    actual === expected
  );
}

export const STRICT_ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

/**
 * Algorithm / Thuật toán: Phân tích chuỗi ngày giờ chuẩn ISO-8601 nghiêm ngặt sang epoch milliseconds.
 * Từ chối mọi chuỗi thường ("dept-2", "1") mà V8 `Date.parse` có thể hiểu nhầm thành mốc thời gian.
 */
export function parseStrictIsoTimestamp(value: string): number | null {
  if (!STRICT_ISO_DATE_PATTERN.test(value)) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

/**
 * Algorithm / Thuật toán: So sánh thứ tự đa kiểu nghiêm ngặt (Strict Polymorphic Total-Order Comparator).
 * Chuyển đổi chuỗi ngày giờ chuẩn ISO-8601 sang epoch milliseconds hoặc giữ nguyên kiểu gốc;
 * từ chối ép kiểu chéo miền (`typeof left !== typeof right`) bằng `Number.NaN` để tránh biến chuỗi mã ("dept-2", "1") thành mốc thời gian.
 */
function compare(actual: RuntimeValue, expected: ExpectedValue): number {
  const left = comparable(actual);
  const right = comparable(expected);
  if (left === null || right === null || typeof left !== typeof right) return Number.NaN;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return String(left).localeCompare(String(right));
}

/**
 * Algorithm / Thuật toán: Chuẩn hóa miền giá trị khả sánh chỉ nhận ngày giờ chuẩn ISO-8601 (Strict ISO-8601 Comparable Normalization).
 */
function comparable(value: RuntimeValue | ExpectedValue): string | number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  const timestamp = parseStrictIsoTimestamp(value);
  return timestamp !== null ? timestamp : value;
}

/**
 * Algorithm / Thuật toán: Kiểm tra khung giờ theo múi giờ có hỗ trợ vắt qua nửa đêm (Timezone-Aware Wrap-Around Time Window).
 *   1. Quy đổi mốc UTC sang giờ-phút-giây địa phương tại `window.timeZone` qua `Intl.DateTimeFormat`.
 *   2. Nếu `start <= end`: `start <= current <= end`; nếu qua đêm (`start > end`): `current >= start || current <= end`.
 */
function timeBetween(value: string, window: TimeWindow): boolean {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return false;
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: window.timeZone,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = Object.fromEntries(
    formatter
      .formatToParts(date)
      .filter((part) => part.type !== 'literal')
      .map((part) => [part.type, Number(part.value)]),
  );
  const current =
    (parts['hour'] ?? 0) * 3600 + (parts['minute'] ?? 0) * 60 + (parts['second'] ?? 0);
  const start = seconds(window.start);
  const end = seconds(window.end);
  return start <= end ? current >= start && current <= end : current >= start || current <= end;
}

/**
 * Algorithm / Thuật toán: Quy đổi chuỗi thời gian `HH:MM[:SS]` sang tổng số giây tính từ 00:00:00.
 */
function seconds(value: string): number {
  const [hours = 0, minutes = 0, secs = 0] = value.split(':').map(Number);
  return hours * 3600 + minutes * 60 + secs;
}

/**
 * Algorithm / Thuật toán: Kiểm tra địa chỉ IP khớp với danh sách nhiều dải mạng CIDR.
 */
function cidrMatchesAny(ip: string, expected: ExpectedValue): boolean {
  const ranges = Array.isArray(expected) ? expected : [expected];
  return ranges.some((range) => typeof range === 'string' && cidrMatch(ip, range));
}
