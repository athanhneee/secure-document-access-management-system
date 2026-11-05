/**
 * @module PolicyContradictionSolver
 * Algorithm: Conjunctive Constraint Satisfiability & Algebraic Contradiction Solver.
 * Phát hiện mâu thuẫn đại số / tập hợp trong nhóm điều kiện hội (AND) của luật ABAC.
 */
import type { ExpectedValue, PolicyCondition } from './abac.types.js';
import { parseStrictIsoTimestamp } from './policy-condition-matcher.js';

/**
 * Algorithm / Thuật toán: Bộ giải phát hiện mâu thuẫn ràng buộc trong một nhóm hội AND (Conjunctive Constraint Contradiction Solver).
 * Mục đích: Phát hiện sớm các cụm điều kiện không bao giờ đồng thời thỏa mãn (unsatisfiable conjunction).
 * Cơ chế hoạt động (gom nhóm theo từng thuộc tính `x` và kiểm tra 6 lớp xung đột đại số / tập hợp):
 *   1. Xung đột sự tồn tại: vừa đòi `EXISTS = true` vừa đòi `EXISTS = false`.
 *   2. Xung đột rỗng - giá trị: đòi `EXISTS = false` nhưng lại áp thêm phép toán so sánh giá trị trên `x`.
 *   3. Xung đột đẳng thức đôi: `x == a` đồng thời `x == b` với `a !== b`.
 *   4. Xung đột đẳng thức - bất đẳng thức: `x == a` đồng thời `x != a`.
 *   5. Xung đột bao hàm / loại trừ tập hợp: `x == a` nhưng `a` không nằm trong tập `IN`, hoặc `a` nằm trong tập `NOT_IN`.
 *   6. Xung đột khoảng chặn dưới - chặn trên: `max(GTE) > min(LTE)` khiến đoạn giao `[lower, upper]` bị rỗng.
 */
export function hasContradiction(conditions: PolicyCondition[]): boolean {
  const byAttribute = new Map<string, PolicyCondition[]>();
  for (const condition of conditions) {
    const existing = byAttribute.get(condition.attribute) ?? [];
    existing.push(condition);
    byAttribute.set(condition.attribute, existing);
  }
  for (const attributeConditions of byAttribute.values()) {
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
    const equals = attributeConditions
      .filter((item) => item.operator === 'EQ')
      .map((item) => item.expected);
    if (new Set(equals.map(canonical)).size > 1) return true;
    const notEquals = new Set(
      attributeConditions
        .filter((item) => item.operator === 'NEQ')
        .map((item) => canonical(item.expected)),
    );
    if (equals.some((value) => notEquals.has(canonical(value)))) return true;
    const included = attributeConditions
      .filter((item) => item.operator === 'IN' && Array.isArray(item.expected))
      .flatMap((item) => item.expected as Array<string | number | boolean>);
    const excluded = new Set(
      attributeConditions
        .filter((item) => item.operator === 'NOT_IN' && Array.isArray(item.expected))
        .flatMap((item) => item.expected as Array<string | number | boolean>)
        .map(canonical),
    );
    if (
      equals.some(
        (value) =>
          included.length > 0 && !included.some((item) => canonical(item) === canonical(value)),
      )
    ) {
      return true;
    }
    if (equals.some((value) => excluded.has(canonical(value)))) return true;
    const lower = attributeConditions
      .filter((item) => item.operator === 'GTE')
      .map((item) => item.expected)
      .sort(compareExpectedValues)
      .at(-1);
    const upper = attributeConditions
      .filter((item) => item.operator === 'LTE')
      .map((item) => item.expected)
      .sort(compareExpectedValues)
      .at(0);
    if (lower !== undefined && upper !== undefined && compareExpectedValues(lower, upper) > 0) {
      return true;
    }
  }
  return false;
}

/**
 * Algorithm / Thuật toán: Tuần tự hóa giá trị kỳ vọng sang chuỗi chuẩn tắc để đối chiếu tập hợp trong O(1) với Set.
 */
function canonical(value: ExpectedValue): string {
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
