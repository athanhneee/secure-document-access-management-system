import type {
  AttributeMetadata,
  VisualConditionGroup,
  VisualObligation,
  VisualPolicyRule,
} from './abac-models';
import { ATTRIBUTE_REGISTRY } from './abac-models';
import { createConditionId } from './policy-ast-helpers';

/**
 * Thuật toán: Quản lý Nhánh Tuyển DNF, Kéo-Thả Liên Nhóm & Tập Nghĩa vụ Thực thi (`policy-group-helpers`)
 * Mục đích: Duy trì cấu trúc tuyển `OR` của các nhóm điều kiện liên hội `AND`, di chuyển nguyên tử điều kiện giữa các nhóm và lọc bảng thuộc tính đa tiêu chí.
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
      if (group.id === srcGroupId) {
        return { ...group, conditions: group.conditions.filter((_, idx) => idx !== srcIndex) };
      }
      if (group.id === targetGroupId) {
        return { ...group, conditions: [...group.conditions, condToMove] };
      }
      return group;
    }),
  };
}

export function toggleRuleObligation(
  obligations: VisualObligation[],
  type: string,
): VisualObligation[] {
  if (obligations.some((o) => o.type === type)) return obligations.filter((o) => o.type !== type);
  if (type === 'MAX_SESSION_MINUTES') {
    return [...obligations, { type: 'MAX_SESSION_MINUTES', minutes: 30 }];
  }
  if (type === 'REQUIRE_WATERMARK') return [...obligations, { type: 'REQUIRE_WATERMARK' }];
  if (type === 'REQUIRE_MFA') return [...obligations, { type: 'REQUIRE_MFA' }];
  if (type === 'FORBID_DOWNLOAD') return [...obligations, { type: 'FORBID_DOWNLOAD' }];
  return [...obligations, { type: 'NO_CACHE' }];
}

export function filterAttributePalette(
  selectedCategory: 'ALL' | 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT',
  searchPalette: string,
  registry: Readonly<Record<string, AttributeMetadata>> = ATTRIBUTE_REGISTRY,
): AttributeMetadata[] {
  const query = searchPalette.toLowerCase();
  return Object.values(registry).filter((attr) => {
    const matchesCategory = selectedCategory === 'ALL' || attr.category === selectedCategory;
    return (
      matchesCategory &&
      (attr.label.toLowerCase().includes(query) ||
        attr.key.toLowerCase().includes(query) ||
        attr.description.toLowerCase().includes(query))
    );
  });
}
