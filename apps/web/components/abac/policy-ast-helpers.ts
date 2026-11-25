import type {
  AttributeMetadata,
  DynamicDepartmentOption,
  ExpectedValue,
  PolicyOperator,
  VisualCondition,
  VisualPolicyRule,
} from './abac-models';
import { ATTRIBUTE_REGISTRY } from './abac-models';
import type { PolicyTemplate } from './policy-templates';

export {
  addDisjunctiveGroup,
  duplicateDisjunctiveGroup,
  filterAttributePalette,
  relocateConditionAcrossGroups,
  toggleRuleObligation,
} from './policy-group-helpers';

let conditionCounter = 0;

/**
 * Thuật toán: Biến Đổi Cây Cú Pháp Trừu Tượng Chính Sách ABAC Có Ràng Buộc Kiểu (`policy-ast-helpers`)
 * Mục đích: Sinh định danh đơn điệu cho các nút vị từ, khởi tạo giá trị kỳ vọng mặc định đồng bộ theo `(attributeMeta, operator)` và tuần tự hóa hai chiều giữa biểu diễn DNF trực quan với JSON AST.
 */
export function createConditionId(): string {
  conditionCounter += 1;
  return `cond-${conditionCounter}`;
}

function defaultExpectedValue(
  meta: AttributeMetadata | undefined,
  operator: PolicyOperator,
): ExpectedValue {
  if (operator === 'TIME_BETWEEN') {
    return { start: '08:00', end: '17:30', timeZone: 'Asia/Ho_Chi_Minh' };
  }
  if (operator === 'BETWEEN') {
    if (meta?.options && meta.options.length > 0) {
      return [meta.options[0]!.value, meta.options[meta.options.length - 1]!.value];
    }
    if (meta?.type === 'NUMBER') {
      return [0, typeof meta.defaultValue === 'number' ? meta.defaultValue : 100];
    }
    return ['', ''];
  }
  if (operator === 'IN' || operator === 'NOT_IN') {
    if (Array.isArray(meta?.defaultValue)) return [...meta.defaultValue];
    if (meta?.defaultValue !== undefined && typeof meta.defaultValue !== 'object') {
      return [meta.defaultValue];
    }
    return [];
  }
  if (operator === 'EXISTS') return true;
  return meta ? meta.defaultValue : '';
}

export const DEFAULT_INITIAL_RULE: VisualPolicyRule = {
  id: 'rule-new-001',
  code: 'POL_DOCUMENT_ACCESS_RESTRICTED',
  name: 'Chính sách truy cập tài liệu mật tiêu chuẩn',
  description:
    'Yêu cầu người dùng kết nối từ mạng nội bộ tổ chức và có cấp thẩm quyền bảo mật phù hợp với mức độ mật của tài liệu.',
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

export function serializePolicyAst(rule: VisualPolicyRule): string {
  return JSON.stringify(rule, null, 2);
}

export function deserializePolicyAst(jsonText: string): VisualPolicyRule {
  const parsed = JSON.parse(jsonText) as VisualPolicyRule;
  if (!parsed.code || !parsed.effect || !Array.isArray(parsed.groups)) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: thiếu thông tin mã chính sách, hiệu lực hoặc danh sách nhóm điều kiện.',
    );
  }
  return parsed;
}

/**
 * Thuật toán: Nhân Bản Mẫu Chính Sách Kèm Ánh Xạ Mã Phòng Ban CSDL Thực Tế (`clonePolicyTemplate`)
 * Mục đích: Thay thế mã phòng ban mẫu (`FINANCE_DEPT`, `AUDIT_DEPT`) sang ID phòng ban thật trong CSDL để mẫu hoạt động đúng ngay khi lưu.
 */
export function clonePolicyTemplate(
  tpl: PolicyTemplate,
  departments?: readonly DynamicDepartmentOption[],
): VisualPolicyRule {
  const cloned = JSON.parse(JSON.stringify(tpl.rule)) as VisualPolicyRule;
  const fallbackDeptId = departments?.[0]?.id ? String(departments[0].id) : '1';
  const financeDeptId =
    departments?.find((d) => d.code.toUpperCase().includes('FINANCE'))?.id ?? fallbackDeptId;
  const auditDeptId =
    departments?.find(
      (d) => d.code.toUpperCase().includes('AUDIT') || d.code.toUpperCase().includes('LEGAL'),
    )?.id ?? fallbackDeptId;

  return {
    ...cloned,
    groups: cloned.groups.map((group) => ({
      ...group,
      conditions: group.conditions.map((cond) => {
        if (
          cond.attribute !== 'subject.departmentId' &&
          cond.attribute !== 'resource.departmentId'
        ) {
          return cond;
        }
        if (cond.expected === 'FINANCE_DEPT') {
          return { ...cond, expected: String(financeDeptId) };
        }
        if (cond.expected === 'AUDIT_DEPT') {
          return { ...cond, expected: String(auditDeptId) };
        }
        return cond;
      }),
    })),
  };
}

export function addConditionToGroup(
  rule: VisualPolicyRule,
  groupId: number,
  attributeKey?: string,
  registry: Readonly<Record<string, AttributeMetadata>> = ATTRIBUTE_REGISTRY,
): VisualPolicyRule {
  const attrKey = attributeKey || 'subject.clearanceRank';
  const meta = registry[attrKey] ?? ATTRIBUTE_REGISTRY[attrKey];
  const initialOp: PolicyOperator = meta ? meta.supportedOperators[0]! : 'EQ';
  const newCondition: VisualCondition = {
    id: createConditionId(),
    attribute: attrKey,
    operator: initialOp,
    expected: defaultExpectedValue(meta, initialOp),
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
  registry: Readonly<Record<string, AttributeMetadata>> = ATTRIBUTE_REGISTRY,
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
            const meta = registry[value as string] ?? ATTRIBUTE_REGISTRY[value as string];
            const nextOp: PolicyOperator = meta ? meta.supportedOperators[0]! : 'EQ';
            return {
              ...cond,
              attribute: value as string,
              operator: nextOp,
              expected: defaultExpectedValue(meta, nextOp),
            };
          }
          if (field === 'operator') {
            const nextOp = value as PolicyOperator;
            const meta = registry[cond.attribute] ?? ATTRIBUTE_REGISTRY[cond.attribute];
            return { ...cond, operator: nextOp, expected: defaultExpectedValue(meta, nextOp) };
          }
          return { ...cond, [field]: value };
        }),
      };
    }),
  };
}
