/**
 * @module PolicyCompiler
 * Algorithm: Deterministic DNF AST Policy Compiler & Attribute Schema Validator.
 * Trình biên dịch chính sách ABAC tất định (Deterministic DNF AST Policy Compiler).
 * Chuyển đổi các bản ghi luật quan hệ phẳng trong cơ sở dữ liệu thành cây cú pháp trừu tượng (AST)
 * dạng chuẩn tuyển (Disjunctive Normal Form - DNF), kiểm tra tính tương thích lược đồ thuộc tính
 * và sắp xếp thứ tự ưu tiên tất định trước khi đưa vào bộ nhớ đệm PDP.
 */
import { ATTRIBUTE_CODE_TO_KEY, CONTEXT_ATTRIBUTES } from './attribute-registry.js';
import type { CompiledPolicy, CompiledPolicyRule, PolicyCondition } from './abac.types.js';
import {
  compareBigIntStrings,
  parseExpected,
  parseObligations,
  parseOperator,
  PolicyCompilationError,
  uniqueSorted,
} from './policy-compiler-parsers.js';
import { validatePolicy } from './policy-validator.js';

export { PolicyCompilationError } from './policy-compiler-parsers.js';

export interface StoredCondition {
  id: bigint;
  definitionCode: string | null;
  contextKey: string | null;
  operator: string;
  expectedValue: unknown;
  group: number;
  sequence: number;
}

export interface StoredRule {
  id: bigint;
  code: string;
  effect: 'PERMIT' | 'DENY';
  priority: number;
  targetResource: string;
  targetAction: 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE' | null;
  combiningAlgorithm: string;
  validFrom: Date;
  validTo: Date | null;
  obligations: unknown;
  conditions: StoredCondition[];
}

export interface StoredDefinition {
  code: string;
  required: boolean;
  scope: 'USER' | 'RESOURCE' | 'ENVIRONMENT';
  valueType: 'STRING' | 'NUMBER' | 'BOOLEAN' | 'DATE' | 'ENUM';
  options: Array<{ valueCode: string; numericRank: number | null }>;
}

/**
 * Algorithm / Thuật toán: Biên dịch tập luật ABAC sang biểu diễn AST DNF bất biến và kiểm chứng toàn cục.
 * Cơ chế hoạt động:
 *   1. Kiểm chứng lược đồ định nghĩa thuộc tính (`validateDefinitions`).
 *   2. Thu thập tập thuộc tính bắt buộc (luôn bao gồm `subject.clearanceRank` và `resource.classificationRank`),
 *      khử trùng lặp và sắp xếp từ điển tất định.
 *   3. Biên dịch từng luật sang cấu trúc DNF và sắp xếp theo khóa kép `(priority ASC, id ASC)`.
 *   4. Chạy bộ kiểm chứng ngữ nghĩa & phát hiện mâu thuẫn (`validatePolicy`); ném lỗi nếu có bất kỳ vi phạm nào.
 */
export function compilePolicy(
  version: bigint,
  definitions: StoredDefinition[],
  storedRules: StoredRule[],
): CompiledPolicy {
  validateDefinitions(definitions);
  const policy: CompiledPolicy = {
    version: version.toString(),
    requiredAttributes: uniqueSorted([
      'subject.clearanceRank',
      'resource.classificationRank',
      ...definitions
        .filter((definition) => definition.required)
        .map((definition) => ATTRIBUTE_CODE_TO_KEY[definition.code])
        .filter((key): key is string => key !== undefined),
    ]),
    rules: storedRules
      .map(compileRule)
      .sort(
        (left, right) => left.priority - right.priority || compareBigIntStrings(left.id, right.id),
      ),
  };
  const issues = validatePolicy(policy, CONTEXT_ATTRIBUTES);
  if (issues.length > 0)
    throw new PolicyCompilationError(uniqueSorted(issues.map((issue) => issue.code)));
  return policy;
}

/**
 * Algorithm / Thuật toán: Dựng cây điều kiện chuẩn tuyển DNF (Disjunctive Normal Form AST Construction) cho từng luật.
 * Cơ chế hoạt động:
 *   1. Sắp xếp danh sách điều kiện phẳng theo bộ ba khóa `(group ASC, sequence ASC, id ASC)`.
 *   2. Phân hoạch các điều kiện vào bảng băm `Map<groupId, PolicyCondition[]>`, trong đó mỗi nhóm là một
 *      mệnh đề hội (AND) và tập các nhóm tạo thành mệnh đề tuyển (OR).
 *   3. Chuẩn hóa toán tử, giá trị kỳ vọng và danh sách nghĩa vụ bảo mật đi kèm.
 */
function compileRule(rule: StoredRule): CompiledPolicyRule {
  if (rule.targetResource !== 'DOCUMENT') throw new PolicyCompilationError(['INVALID_TARGET']);
  if (rule.combiningAlgorithm !== 'DENY_OVERRIDES') {
    throw new PolicyCompilationError(['INVALID_COMBINING_ALGORITHM']);
  }
  const groups = new Map<number, PolicyCondition[]>();
  for (const condition of [...rule.conditions].sort(
    (left, right) =>
      left.group - right.group || left.sequence - right.sequence || Number(left.id - right.id),
  )) {
    const attribute =
      condition.contextKey ?? ATTRIBUTE_CODE_TO_KEY[condition.definitionCode ?? ''] ?? '';
    const values = groups.get(condition.group) ?? [];
    values.push({
      id: condition.id.toString(),
      attribute,
      operator: parseOperator(condition.operator),
      expected: parseExpected(condition.expectedValue),
    });
    groups.set(condition.group, values);
  }
  return {
    id: rule.id.toString(),
    code: rule.code,
    effect: rule.effect,
    priority: rule.priority,
    targetResource: 'DOCUMENT',
    targetAction: rule.targetAction,
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: rule.validFrom.toISOString(),
    validTo: rule.validTo?.toISOString() ?? null,
    groups: [...groups.entries()]
      .sort(([left], [right]) => left - right)
      .map(([id, conditions]) => ({ id, conditions })),
    obligations: parseObligations(rule.obligations),
  };
}

/**
 * Algorithm / Thuật toán: Kiểm tra tính nhất quán kiểu và miền phạm vi của từ điển thuộc tính (Schema Type-Scope Alignment).
 * Đối chiếu ánh xạ giữa phạm vi lưu trữ (`USER`/`RESOURCE`/`ENVIRONMENT`) với tiền tố ngữ cảnh
 * (`subject`/`resource`/`environment`), kiểm tra kiểu dữ liệu chuẩn hóa và bắt buộc `CLEARANCE_LEVEL` có thứ bậc số.
 */
function validateDefinitions(definitions: StoredDefinition[]): void {
  const issues: string[] = [];
  for (const definition of definitions) {
    const key = ATTRIBUTE_CODE_TO_KEY[definition.code];
    if (!key) continue;
    const descriptor = CONTEXT_ATTRIBUTES[key];
    const expectedScope = key.split('.')[0];
    const scopeMatches =
      (expectedScope === 'subject' && definition.scope === 'USER') ||
      (expectedScope === 'resource' && definition.scope === 'RESOURCE') ||
      (expectedScope === 'environment' && definition.scope === 'ENVIRONMENT');
    const normalizedType =
      definition.code === 'CLEARANCE_LEVEL'
        ? 'NUMBER'
        : definition.code === 'SOURCE_IP'
          ? 'IP'
          : definition.valueType === 'ENUM'
            ? 'STRING'
            : definition.valueType;
    if (!descriptor || !scopeMatches || normalizedType !== descriptor.type) {
      issues.push('INVALID_ATTRIBUTE_DEFINITION');
    }
    if (
      definition.code === 'CLEARANCE_LEVEL' &&
      (definition.options.length === 0 ||
        definition.options.some((option) => option.numericRank === null))
    ) {
      issues.push('INVALID_ATTRIBUTE_OPTION');
    }
  }
  if (issues.length > 0) throw new PolicyCompilationError(uniqueSorted(issues));
}
