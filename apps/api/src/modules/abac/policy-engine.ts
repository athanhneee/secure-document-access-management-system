/**
 * @module PolicyEngine
 * Algorithm: Deterministic ABAC Policy Decision Point (Bell-LaPadula + DNF + XACML DENY_OVERRIDES).
 * Động cơ đánh giá chính sách ABAC tất định (Deterministic Policy Decision Point - PDP).
 * Kết hợp mô hình kiểm soát truy cập bắt buộc Bell-LaPadula (Simple Security Property),
 * đánh giá biểu thức chính sách dạng chuẩn tuyển (Disjunctive Normal Form - DNF),
 * thuật toán kết hợp luật XACML DENY_OVERRIDES (mặc định từ chối Fail-Closed)
 * và gộp nghĩa vụ bảo mật chặt nhất.
 */
import { CONTEXT_ATTRIBUTES } from './attribute-registry.js';
import type {
  CompiledPolicy,
  PdpResult,
  PolicyEvaluationInput,
  PolicyObligation,
} from './abac.types.js';
import {
  flattenContext,
  isMissingAttribute,
  matchesCondition,
  parseStrictIsoTimestamp,
} from './policy-condition-matcher.js';
import { validatePolicy } from './policy-validator.js';

export { cidrMatch } from './cidr.js';

const obligationOrder: Readonly<Record<PolicyObligation['type'], number>> = {
  REQUIRE_WATERMARK: 0,
  REQUIRE_MFA: 1,
  MAX_SESSION_MINUTES: 2,
  FORBID_DOWNLOAD: 3,
  NO_CACHE: 4,
};

/**
 * Algorithm / Thuật toán: Đánh giá quyết định chính sách ABAC kết hợp Bell-LaPadula, DNF & XACML DENY_OVERRIDES.
 * Mục đích: Xác định quyết định cho phép (PERMIT) hoặc từ chối (DENY) cùng tập nghĩa vụ kèm theo.
 * Cơ chế hoạt động:
 *   1. Kiểm chứng tính hợp lệ tĩnh của chính sách đã biên dịch; từ chối ngay (Fail-Closed) nếu lỗi.
 *   2. Trải phẳng ngữ cảnh thuộc tính và kiểm tra sự hiện diện của mọi thuộc tính bắt buộc.
 *   3. Kiểm tra bất biến thống trị độ mật Bell-LaPadula (Simple Security / No Read Up):
 *      `subject.clearanceRank >= resource.classificationRank`, nếu thấp hơn trả về INSUFFICIENT_CLEARANCE.
 *   4. Sắp xếp các luật theo độ ưu tiên tăng dần (`priority`, phá hòa tất định theo `id`) và lọc các luật
 *      khớp tài nguyên, hành động, khoảng hiệu lực thời gian `[validFrom, validTo)` và thỏa mãn biểu thức
 *      DNF: tồn tại ít nhất một nhóm OR mà mọi điều kiện con bên trong đều đúng (AND).
 *   5. Kết hợp kết quả theo chuẩn XACML DENY_OVERRIDES: bất kỳ luật DENY nào khớp sẽ thắng tuyệt đối;
 *      nếu không có luật PERMIT nào khớp thì rơi về DEFAULT_DENY; ngược lại trả về PERMIT kèm nghĩa vụ đã gộp.
 */
export function evaluatePolicy(policy: CompiledPolicy, input: PolicyEvaluationInput): PdpResult {
  if (validatePolicy(policy, CONTEXT_ATTRIBUTES).length > 0) return deny(policy, 'INVALID_POLICY');
  const attributes = flattenContext(input);
  if (policy.requiredAttributes.some((key) => isMissingAttribute(attributes[key]))) {
    return deny(policy, 'MISSING_REQUIRED_ATTRIBUTE');
  }
  // Thuật toán Bell-LaPadula Clearance Dominance: chủ thể phải có cấp độ mật >= cấp phân loại tài liệu
  if (input.subject.clearanceRank === null || input.resource.classificationRank === null) {
    return deny(policy, 'MISSING_REQUIRED_ATTRIBUTE');
  }
  if (input.subject.clearanceRank < input.resource.classificationRank) {
    return deny(policy, 'INSUFFICIENT_CLEARANCE');
  }

  // Thuật toán đánh giá DNF (OR của các cụm AND) và sắp xếp thứ tự ưu tiên tất định
  const now = parseStrictIsoTimestamp(input.environment.currentTime);
  if (now === null) {
    return deny(policy, 'MISSING_REQUIRED_ATTRIBUTE');
  }
  const rules = [...policy.rules].sort(
    (left, right) => left.priority - right.priority || compareIds(left.id, right.id),
  );
  const matched = rules.filter(
    (rule) =>
      rule.targetResource === input.resourceType &&
      (rule.targetAction === null || rule.targetAction === input.action) &&
      Date.parse(rule.validFrom) <= now &&
      (rule.validTo === null || now < Date.parse(rule.validTo)) &&
      rule.groups.some((group) =>
        group.conditions.every((condition) => matchesCondition(condition, attributes)),
      ),
  );
  // Thuật toán kết hợp XACML DENY_OVERRIDES kết hợp Default-Deny
  const matchedRuleIds = matched.map((rule) => rule.id);
  if (matched.some((rule) => rule.effect === 'DENY')) {
    return { ...deny(policy, 'EXPLICIT_DENY'), matchedRuleIds };
  }
  const permitted = matched.filter((rule) => rule.effect === 'PERMIT');
  if (permitted.length === 0) return deny(policy, 'DEFAULT_DENY');
  return {
    decision: 'PERMIT',
    reasonCode: 'POLICY_PERMIT',
    matchedRuleIds,
    obligations: mergeObligations(permitted.flatMap((rule) => rule.obligations)),
    policyVersion: policy.version,
  };
}

/**
 * Algorithm / Thuật toán: Khởi tạo phản hồi từ chối chuẩn hóa (Fail-Closed Deny Builder).
 * Mục đích: Bảo đảm mọi nhánh từ chối đều xóa rỗng danh sách nghĩa vụ và gắn đúng phiên bản chính sách.
 */
function deny(policy: CompiledPolicy, reasonCode: PdpResult['reasonCode']): PdpResult {
  return {
    decision: 'DENY',
    reasonCode,
    matchedRuleIds: [],
    obligations: [],
    policyVersion: policy.version,
  };
}

/**
 * Algorithm / Thuật toán: Hợp nhất nghĩa vụ bảo mật theo nguyên lý chặt nhất (Most-Restrictive Obligation Merging).
 *   - Khử trùng lặp các cờ nghĩa vụ nhị phân bằng cấu trúc Set.
 *   - Với `MAX_SESSION_MINUTES`, lấy giá trị nhỏ nhất `Math.min(...maximums)` để áp giới hạn phiên ngắn nhất.
 *   - Sắp xếp đầu ra theo bảng thứ tự cố định `obligationOrder` nhằm đảm bảo tính tất định.
 */
function mergeObligations(obligations: PolicyObligation[]): PolicyObligation[] {
  const types = new Set(obligations.map((item) => item.type));
  const maximums = obligations
    .filter(
      (item): item is Extract<PolicyObligation, { type: 'MAX_SESSION_MINUTES' }> =>
        item.type === 'MAX_SESSION_MINUTES',
    )
    .map((item) => item.minutes);
  const result: PolicyObligation[] = [...types]
    .filter((type) => type !== 'MAX_SESSION_MINUTES')
    .map((type) => ({ type }) as PolicyObligation);
  if (maximums.length > 0)
    result.push({ type: 'MAX_SESSION_MINUTES', minutes: Math.min(...maximums) });
  return result.sort((left, right) => obligationOrder[left.type] - obligationOrder[right.type]);
}

/**
 * Algorithm / Thuật toán: Phá hòa định danh số nguyên lớn (BigInt Tie-Breaking Comparator).
 * Mục đích: So sánh chính xác ID 64-bit dạng chuỗi mà không bị tràn độ chính xác IEEE-754 Number.
 */
function compareIds(left: string, right: string): number {
  try {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1 : a > b ? 1 : 0;
  } catch {
    return left.localeCompare(right);
  }
}
