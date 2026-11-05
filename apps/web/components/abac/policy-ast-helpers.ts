import type {
  VisualPolicyRule,
  VisualCondition,
  VisualConditionGroup,
  VisualObligation,
  AttributeMetadata,
} from './abac-models';
import { ATTRIBUTE_REGISTRY } from './abac-models';
import type { PolicyTemplate } from './policy-templates';

let conditionCounter = 0;

/**
 * Algorithm / Thuật toán: Bộ Đếm Đơn Điệu Sinh Định Danh Nút AST (Monotonic Node ID Generator)
 */
export function createConditionId(): string {
  conditionCounter += 1;
  return `cond-${conditionCounter}`;
}

export const DEFAULT_INITIAL_RULE: VisualPolicyRule = {
  id: 'rule-new-001',
  code: 'POL_DOCUMENT_ACCESS_RESTRICTED',
  name: 'Chính sách Truy cập Tài liệu Mật Tiêu chuẩn',
  description:
    'Yêu cầu nhân viên kết nối từ mạng nội bộ cơ quan và có cấp bậc an ninh phù hợp với cấp độ mật của tài liệu.',
  effect: 'PERMIT',
  priority: 10,
  targetResource: 'DOCUMENT',
  targetAction: 'VIEW',
  combiningAlgorithm: 'DENY_OVERRIDES',
  groups: [
    {
      id: 1,
      conditions: [
        { id: 'c-1', attribute: 'environment.trustedNetwork', operator: 'EQ', expected: true },
        { id: 'c-2', attribute: 'subject.clearanceRank', operator: 'GTE', expected: 2 },
      ],
    },
  ],
  obligations: [{ type: 'REQUIRE_WATERMARK' }],
};

/**
 * Algorithm / Thuật toán: Chuẩn Hóa & Tuần Tự Hóa Trạng Thái DNF Sang JSON AST (DNF-to-AST Serialization)
 */
export function serializePolicyAst(rule: VisualPolicyRule): string {
  return JSON.stringify(rule, null, 2);
}

/**
 * Algorithm / Thuật toán: Giải Tuần Tự Hóa & Kiểm Định Lược Đồ JSON AST Sang Biểu Diễn DNF (AST-to-DNF Schema Validation)
 * Cơ chế: Phân tích `JSON.parse` và kiểm tra bất biến `code`, `effect`, `groups` trước khi dựng lại cây DNF.
 */
export function deserializePolicyAst(jsonText: string): VisualPolicyRule {
  const parsed = JSON.parse(jsonText) as VisualPolicyRule;
  if (!parsed.code || !parsed.effect || !Array.isArray(parsed.groups)) {
    throw new Error('Cấu trúc JSON không hợp lệ: Thiếu các trường code, effect hoặc groups.');
  }
  return parsed;
}

/**
 * Algorithm / Thuật toán: Sao Chép Sâu Cây Mẫu Chính Sách (AST Template Deep Clone)
 */
export function clonePolicyTemplate(tpl: PolicyTemplate): VisualPolicyRule {
  return JSON.parse(JSON.stringify(tpl.rule)) as VisualPolicyRule;
}

/**
 * Algorithm / Thuật toán: Bổ Sung & Chỉnh Sửa Nút Điều Kiện Liên Hội Có Ràng Buộc Kiểu (Type-Safe Conjunctive AST Node Operations)
 */
export function addConditionToGroup(
  rule: VisualPolicyRule,
  groupId: number,
  attributeKey?: string,
): VisualPolicyRule {
  const attrKey = attributeKey || 'subject.clearanceRank';
  const meta = ATTRIBUTE_REGISTRY[attrKey];
  const newCondition: VisualCondition = {
    id: createConditionId(),
    attribute: attrKey,
    operator: meta ? meta.supportedOperators[0]! : 'EQ',
    expected: meta ? meta.defaultValue : '',
  };
  return {
    ...rule,
    groups: rule.groups.map((g) =>
      g.id === groupId ? { ...g, conditions: [...g.conditions, newCondition] } : g,
    ),
  };
}

export function removeConditionFromGroup(
  rule: VisualPolicyRule,
  groupId: number,
  conditionId: string,
): VisualPolicyRule {
  return {
    ...rule,
    groups: rule.groups.map((g) =>
      g.id === groupId ? { ...g, conditions: g.conditions.filter((c) => c.id !== conditionId) } : g,
    ),
  };
}

export function duplicateConditionInGroup(
  rule: VisualPolicyRule,
  groupId: number,
  condition: VisualCondition,
): VisualPolicyRule {
  const cloned: VisualCondition = { ...condition, id: createConditionId() };
  return {
    ...rule,
    groups: rule.groups.map((g) =>
      g.id === groupId ? { ...g, conditions: [...g.conditions, cloned] } : g,
    ),
  };
}

export function moveConditionInGroup(
  rule: VisualPolicyRule,
  groupId: number,
  index: number,
  direction: 'up' | 'down',
): VisualPolicyRule | null {
  const targetGroup = rule.groups.find((g) => g.id === groupId);
  if (!targetGroup) return null;
  const newConditions = [...targetGroup.conditions];
  const targetIndex = direction === 'up' ? index - 1 : index + 1;
  if (targetIndex < 0 || targetIndex >= newConditions.length) return null;
  const temp = newConditions[index]!;
  newConditions[index] = newConditions[targetIndex]!;
  newConditions[targetIndex] = temp;
  return {
    ...rule,
    groups: rule.groups.map((g) => (g.id === groupId ? { ...g, conditions: newConditions } : g)),
  };
}

export function updateConditionField(
  rule: VisualPolicyRule,
  groupId: number,
  conditionId: string,
  field: keyof VisualCondition,
  value: unknown,
): VisualPolicyRule {
  return {
    ...rule,
    groups: rule.groups.map((group) => {
      if (group.id !== groupId) return group;
      return {
        ...group,
        conditions: group.conditions.map((cond) => {
          if (cond.id !== conditionId) return cond;
          if (field === 'attribute') {
            const meta = ATTRIBUTE_REGISTRY[value as string];
            return {
              ...cond,
              attribute: value as string,
              operator: meta ? meta.supportedOperators[0]! : 'EQ',
              expected: meta ? meta.defaultValue : '',
            };
          }
          return { ...cond, [field]: value };
        }),
      };
    }),
  };
}

/**
 * Algorithm / Thuật toán: Quản Lý Nhánh Tuyển DNF & Kéo-Thả Liên Nhóm (Disjunctive OR-Clause & Cross-Group AST Relocation)
 */
export function addDisjunctiveGroup(rule: VisualPolicyRule): VisualPolicyRule {
  const nextId = rule.groups.length > 0 ? Math.max(...rule.groups.map((g) => g.id)) + 1 : 1;
  const newGroup: VisualConditionGroup = {
    id: nextId,
    conditions: [
      {
        id: createConditionId(),
        attribute: 'environment.trustedNetwork',
        operator: 'EQ',
        expected: true,
      },
    ],
  };
  return { ...rule, groups: [...rule.groups, newGroup] };
}

export function duplicateDisjunctiveGroup(
  rule: VisualPolicyRule,
  group: VisualConditionGroup,
): VisualPolicyRule {
  const nextId = Math.max(...rule.groups.map((g) => g.id)) + 1;
  return {
    ...rule,
    groups: [
      ...rule.groups,
      { id: nextId, conditions: group.conditions.map((c) => ({ ...c, id: createConditionId() })) },
    ],
  };
}

export function relocateConditionAcrossGroups(
  rule: VisualPolicyRule,
  srcGroupId: number,
  srcIndex: number,
  targetGroupId: number,
): VisualPolicyRule | null {
  if (srcGroupId === targetGroupId) return null;
  const condToMove = rule.groups.find((g) => g.id === srcGroupId)?.conditions[srcIndex];
  if (!condToMove) return null;
  return {
    ...rule,
    groups: rule.groups.map((group) => {
      if (group.id === srcGroupId)
        return { ...group, conditions: group.conditions.filter((_, idx) => idx !== srcIndex) };
      if (group.id === targetGroupId)
        return { ...group, conditions: [...group.conditions, condToMove] };
      return group;
    }),
  };
}

/**
 * Algorithm / Thuật toán: Quản Lý Tập Nghĩa Vụ Thực Thi Duy Nhất Theo Loại & Lọc Đa Tiêu Chí Thuộc Tính
 */
export function toggleRuleObligation(
  obligations: VisualObligation[],
  type: string,
): VisualObligation[] {
  if (obligations.some((o) => o.type === type)) return obligations.filter((o) => o.type !== type);
  if (type === 'MAX_SESSION_MINUTES')
    return [...obligations, { type: 'MAX_SESSION_MINUTES', minutes: 30 }];
  if (type === 'REQUIRE_WATERMARK') return [...obligations, { type: 'REQUIRE_WATERMARK' }];
  if (type === 'REQUIRE_MFA') return [...obligations, { type: 'REQUIRE_MFA' }];
  if (type === 'FORBID_DOWNLOAD') return [...obligations, { type: 'FORBID_DOWNLOAD' }];
  return [...obligations, { type: 'NO_CACHE' }];
}

export function filterAttributePalette(
  selectedCategory: 'ALL' | 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT',
  searchPalette: string,
): AttributeMetadata[] {
  const query = searchPalette.toLowerCase();
  return Object.values(ATTRIBUTE_REGISTRY).filter((attr) => {
    const matchesCategory = selectedCategory === 'ALL' || attr.category === selectedCategory;
    return (
      matchesCategory &&
      (attr.label.toLowerCase().includes(query) ||
        attr.key.toLowerCase().includes(query) ||
        attr.description.toLowerCase().includes(query))
    );
  });
}
