/**
 * @module PolicyContradictionSolver
 * Algorithm: Conjunctive Constraint Satisfiability & Algebraic Contradiction Solver (`BUG-050`).
 * Phát hiện mâu thuẫn đại số / tập hợp / khoảng giá trị trong nhóm điều kiện hội (AND) của luật ABAC.
 */
import type { AttributeDescriptor, ExpectedValue, PolicyCondition } from './abac.types.js';
import { CONTEXT_ATTRIBUTES } from './attribute-registry.js';
import { canonicalizeIpAddress } from './cidr.js';
import { parseStrictIsoTimestamp } from './policy-condition-matcher.js';

type ScalarCandidate = string | number | boolean;

function isScalarCandidate(value: unknown): value is ScalarCandidate {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function isOrderableScalar(value: unknown): value is string | number {
  return (typeof value === 'number' && Number.isFinite(value)) || typeof value === 'string';
}

/**
 * Algorithm / Thuật toán: Bộ giải phát hiện mâu thuẫn ràng buộc trong một nhóm hội AND (`hasContradiction`, `BUG-050`).
 * Cơ chế hoạt động (gom nhóm theo từng thuộc tính `x` và phân nhánh mảng đa trị / vô hướng):
 *   1. Xung đột sự tồn tại: vừa đòi `EXISTS = true` vừa đòi `EXISTS = false`, hoặc đòi `EXISTS = false` kèm toán tử giá trị khác.
 *   2. Nhánh thuộc tính mảng đa trị (`subject.projects` / `multiValue === true`):
 *      - Cho phép hội nhiều `EQ` (`EQ "A" AND EQ "B"` khả thỏa bởi `["A", "B"]`).
 *      - Báo mâu thuẫn khi phần tử bắt buộc (`EQ`) rơi vào `NEQ ∪ NOT_IN`, hoặc khi bất kỳ tập `IN` nào bị `NEQ ∪ NOT_IN` phủ kín thành rỗng.
 *   3. Nhánh thuộc tính vô hướng (`multiValue !== true`):
 *      - Tính giao (intersection) của toàn bộ tập ứng viên từ mọi điều kiện `IN` và `EQ` (cùng miền `{true, false}` nếu kiểu `BOOLEAN`),
 *        trừ đi tập cấm `NEQ ∪ NOT_IN`; nếu tập kết quả rỗng -> mâu thuẫn.
 *      - Gom cận `[lower, upper]` từ cả `GTE`, `LTE`, `BETWEEN` và `EQ`; báo mâu thuẫn nếu `lower > upper`,
 *        hoặc `lower === upper` rơi vào tập cấm `NEQ ∪ NOT_IN`, hoặc không còn ứng viên nào của `allowedSet` nằm trong `[lower, upper]`.
 */
export function hasContradiction(
  conditions: PolicyCondition[],
  attributes: Readonly<Record<string, AttributeDescriptor>> = CONTEXT_ATTRIBUTES,
): boolean {
  const byAttribute = new Map<string, PolicyCondition[]>();
  for (const condition of conditions) {
    const existing = byAttribute.get(condition.attribute) ?? [];
    existing.push(condition);
    byAttribute.set(condition.attribute, existing);
  }

  for (const [attributeKey, attributeConditions] of byAttribute.entries()) {
    const existence = attributeConditions
      .filter((item) => item.operator === 'EXISTS')
      .map((item) => item.expected);
    if (new Set(existence).size > 1) return true;
    if (
      existence.includes(false) &&
      attributeConditions.some((item) => item.operator !== 'EXISTS')
    ) {
      return true;
    }

    const descriptor = Object.hasOwn(attributes, attributeKey)
      ? attributes[attributeKey]
      : undefined;
    const attrType = descriptor?.type;
    const isMultiValue = descriptor?.multiValue === true || attributeKey === 'subject.projects';

    const rawForbiddenValues: ScalarCandidate[] = [];
    const forbiddenKeys = new Set<string>();
    for (const item of attributeConditions) {
      if (item.operator === 'NEQ' && isScalarCandidate(item.expected)) {
        rawForbiddenValues.push(item.expected);
        forbiddenKeys.add(canonical(item.expected, attrType));
      } else if (item.operator === 'NOT_IN' && Array.isArray(item.expected)) {
        for (const elem of item.expected) {
          if (isScalarCandidate(elem)) {
            rawForbiddenValues.push(elem);
            forbiddenKeys.add(canonical(elem, attrType));
          }
        }
      }
    }

    if (isMultiValue) {
      for (const item of attributeConditions) {
        if (item.operator === 'EQ') {
          if (forbiddenKeys.has(canonical(item.expected, attrType))) {
            return true;
          }
        } else if (item.operator === 'IN') {
          if (!Array.isArray(item.expected)) {
            return true;
          }
          const surviving = item.expected.filter(
            (candidate) => !forbiddenKeys.has(canonical(candidate, attrType)),
          );
          if (surviving.length === 0) {
            return true;
          }
        }
      }
      continue;
    }

    let allowedMap: Map<string, ScalarCandidate> | null = null;
    const intersectAllowed = (candidates: readonly ScalarCandidate[]): void => {
      if (allowedMap === null) {
        allowedMap = new Map<string, ScalarCandidate>();
        for (const candidate of candidates) {
          allowedMap.set(canonical(candidate, attrType), candidate);
        }
        return;
      }
      const incoming = new Set(candidates.map((candidate) => canonical(candidate, attrType)));
      for (const existingKey of [...allowedMap.keys()]) {
        if (!incoming.has(existingKey)) {
          allowedMap.delete(existingKey);
        }
      }
    };

    for (const item of attributeConditions) {
      if (item.operator === 'EQ' && isScalarCandidate(item.expected)) {
        intersectAllowed([item.expected]);
      } else if (item.operator === 'IN' && Array.isArray(item.expected)) {
        intersectAllowed(item.expected.filter(isScalarCandidate));
      }
    }

    if (
      descriptor?.type === 'BOOLEAN' &&
      allowedMap === null &&
      attributeConditions.some((item) => item.operator !== 'EXISTS' || item.expected === true)
    ) {
      intersectAllowed([true, false]);
    }

    if (allowedMap !== null) {
      const currentAllowed: Map<string, ScalarCandidate> = allowedMap;
      for (const forbiddenKey of forbiddenKeys) {
        currentAllowed.delete(forbiddenKey);
      }
      if (currentAllowed.size === 0) {
        return true;
      }
    }

    const hasRangeOperator = attributeConditions.some(
      (item) => item.operator === 'GTE' || item.operator === 'LTE' || item.operator === 'BETWEEN',
    );
    const lowerBounds: Array<string | number> = [];
    const upperBounds: Array<string | number> = [];

    for (const item of attributeConditions) {
      if (item.operator === 'GTE' && isOrderableScalar(item.expected)) {
        lowerBounds.push(item.expected);
      } else if (item.operator === 'LTE' && isOrderableScalar(item.expected)) {
        upperBounds.push(item.expected);
      } else if (
        item.operator === 'BETWEEN' &&
        Array.isArray(item.expected) &&
        item.expected.length === 2 &&
        isOrderableScalar(item.expected[0]) &&
        isOrderableScalar(item.expected[1])
      ) {
        if (compareExpectedValues(item.expected[0], item.expected[1]) > 0) {
          return true;
        }
        lowerBounds.push(item.expected[0]);
        upperBounds.push(item.expected[1]);
      } else if (hasRangeOperator && item.operator === 'EQ' && isOrderableScalar(item.expected)) {
        lowerBounds.push(item.expected);
        upperBounds.push(item.expected);
      }
    }

    let lower: string | number | undefined;
    for (const candidate of lowerBounds) {
      if (lower === undefined || compareExpectedValues(candidate, lower) > 0) {
        lower = candidate;
      }
    }

    let upper: string | number | undefined;
    for (const candidate of upperBounds) {
      if (upper === undefined || compareExpectedValues(candidate, upper) < 0) {
        upper = candidate;
      }
    }

    if (lower !== undefined && upper !== undefined) {
      const boundOrder = compareExpectedValues(lower, upper);
      if (boundOrder > 0) {
        return true;
      }
      if (boundOrder === 0) {
        const collapsedPointForbidden =
          forbiddenKeys.has(canonical(lower, attrType)) ||
          forbiddenKeys.has(canonical(upper, attrType)) ||
          rawForbiddenValues.some(
            (fv) => typeof fv === typeof lower && compareExpectedValues(fv, lower) === 0,
          );
        if (collapsedPointForbidden) {
          return true;
        }
      }
    }

    if (allowedMap !== null && (lower !== undefined || upper !== undefined)) {
      const currentAllowed: Map<string, ScalarCandidate> = allowedMap;
      let survivingInBounds = 0;
      for (const candidate of currentAllowed.values()) {
        const passesLower = lower === undefined || compareExpectedValues(candidate, lower) >= 0;
        const passesUpper = upper === undefined || compareExpectedValues(candidate, upper) <= 0;
        if (passesLower && passesUpper) {
          survivingInBounds += 1;
        }
      }
      if (survivingInBounds === 0) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Algorithm / Thuật toán: Tuần tự hóa giá trị kỳ vọng sang chuỗi chuẩn tắc (chuẩn hóa IP qua `canonicalizeIpAddress`
 * và mốc thời gian ISO-8601 sang epoch ms qua `parseStrictIsoTimestamp`) để đối chiếu tập hợp đồng nhất 1-1 với runtime `equal()` (`HIGH-08`).
 */
function canonical(value: ExpectedValue, type?: AttributeDescriptor['type']): string {
  if (typeof value === 'string') {
    if (type === 'IP') {
      const normalizedIp = canonicalizeIpAddress(value);
      if (normalizedIp !== null) return `ip:${normalizedIp}`;
    }
    if (type === 'DATE') {
      const ts = parseStrictIsoTimestamp(value);
      if (ts !== null) return `date:${ts}`;
    }
  }
  return JSON.stringify(value);
}

/**
 * Algorithm / Thuật toán: So sánh thứ tự hai giá trị kỳ vọng (hỗ trợ số, ngày giờ chuẩn ISO-8601 và chuỗi từ điển).
 */
export function compareExpectedValues(left: ExpectedValue, right: ExpectedValue): number {
  const leftIso = typeof left === 'string' ? parseStrictIsoTimestamp(left) : null;
  const rightIso = typeof right === 'string' ? parseStrictIsoTimestamp(right) : null;
  const a = leftIso !== null ? leftIso : left;
  const b = rightIso !== null ? rightIso : right;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b));
}
