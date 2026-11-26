import type {
  AttributeMetadata,
  DynamicDepartmentOption,
  ExpectedValue,
  PolicyOperator,
  TargetAction,
  VisualCondition,
  VisualConditionGroup,
  VisualObligation,
  VisualPolicyRule,
} from './abac-models';
import { ATTRIBUTE_REGISTRY, POLICY_OPERATORS } from './abac-models';
import type { PolicyTemplate } from './policy-templates';

export {
  addDisjunctiveGroup,
  duplicateDisjunctiveGroup,
  filterAttributePalette,
  relocateConditionAcrossGroups,
  toggleRuleObligation,
} from './policy-group-helpers';

export const MIN_SESSION_MINUTES = 1;
export const MAX_SESSION_MINUTES = 1440;
export const DEFAULT_SESSION_MINUTES = 30;

const VALID_TARGET_ACTIONS = new Set<TargetAction>([
  'ALL',
  'DISCOVER',
  'VIEW',
  'DOWNLOAD',
  'SHARE',
  'MANAGE',
]);

const VALID_SIMPLE_OBLIGATIONS = new Set([
  'REQUIRE_WATERMARK',
  'REQUIRE_MFA',
  'FORBID_DOWNLOAD',
  'NO_CACHE',
]);

export function clampSessionMinutes(
  value: number,
  fallback: number = DEFAULT_SESSION_MINUTES,
): number {
  const safeFallback = Number.isFinite(fallback)
    ? Math.min(MAX_SESSION_MINUTES, Math.max(MIN_SESSION_MINUTES, Math.trunc(fallback)))
    : DEFAULT_SESSION_MINUTES;
  if (!Number.isFinite(value)) return safeFallback;
  return Math.min(MAX_SESSION_MINUTES, Math.max(MIN_SESSION_MINUTES, Math.trunc(value)));
}

export function parseSessionMinutesDraft(
  draft: string,
): { valid: true; minutes: number } | { valid: false; message: string } {
  const trimmed = draft.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      message: `Vui lòng nhập thời gian giới hạn phiên đọc (từ ${MIN_SESSION_MINUTES} đến ${MAX_SESSION_MINUTES} phút).`,
    };
  }
  if (!/^[+-]?\d+$/u.test(trimmed)) {
    return {
      valid: false,
      message: `Thời gian giới hạn phiên phải là số nguyên (từ ${MIN_SESSION_MINUTES} đến ${MAX_SESSION_MINUTES} phút).`,
    };
  }
  const parsed = Number(trimmed);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < MIN_SESSION_MINUTES ||
    parsed > MAX_SESSION_MINUTES
  ) {
    return {
      valid: false,
      message: `Thời gian giới hạn phiên phải nằm trong khoảng từ ${MIN_SESSION_MINUTES} đến ${MAX_SESSION_MINUTES} phút.`,
    };
  }
  return { valid: true, minutes: parsed };
}

export function normalizeSessionMinutesDraftOnBlur(
  draft: string,
  fallbackMinutes: number = DEFAULT_SESSION_MINUTES,
): number {
  const trimmed = draft.trim();
  if (trimmed.length === 0) {
    return clampSessionMinutes(fallbackMinutes);
  }
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) {
    return clampSessionMinutes(fallbackMinutes);
  }
  return clampSessionMinutes(Math.trunc(parsed), fallbackMinutes);
}

export function validateVisualPolicyRule(rule: VisualPolicyRule): string | null {
  if (!rule.code || rule.code.trim().length < 2 || rule.code.trim().length > 80) {
    return 'Mã chính sách bắt buộc từ 2 đến 80 ký tự.';
  }
  if (!rule.name || rule.name.trim().length < 2 || rule.name.trim().length > 180) {
    return 'Tên chính sách bắt buộc từ 2 đến 180 ký tự.';
  }
  if (!Number.isInteger(rule.priority) || rule.priority < 1 || rule.priority > 100_000) {
    return 'Độ ưu tiên của chính sách phải là số nguyên từ 1 đến 100000.';
  }
  if (!Array.isArray(rule.groups) || rule.groups.length === 0) {
    return 'Chính sách truy cập phải có ít nhất một nhóm điều kiện.';
  }
  for (const group of rule.groups) {
    if (!Array.isArray(group.conditions) || group.conditions.length === 0) {
      return `Nhóm điều kiện #${group.id} không được để trống.`;
    }
  }
  for (const ob of rule.obligations) {
    if (ob.type === 'MAX_SESSION_MINUTES') {
      if (
        typeof ob.minutes !== 'number' ||
        !Number.isInteger(ob.minutes) ||
        ob.minutes < MIN_SESSION_MINUTES ||
        ob.minutes > MAX_SESSION_MINUTES
      ) {
        return `Thời gian giới hạn phiên (MAX_SESSION_MINUTES) phải là số nguyên từ ${MIN_SESSION_MINUTES} đến ${MAX_SESSION_MINUTES} phút.`;
      }
    } else if (!VALID_SIMPLE_OBLIGATIONS.has(ob.type)) {
      return 'Danh sách nghĩa vụ chứa loại ràng buộc không hợp lệ.';
    }
  }
  return null;
}

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
  if (operator === 'CIDR_MATCH') {
    if (Array.isArray(meta?.defaultValue)) {
      return meta.defaultValue.map((item) => String(item));
    }
    if (typeof meta?.defaultValue === 'string' && meta.defaultValue.trim()) {
      return [meta.defaultValue.trim()];
    }
    return ['192.168.1.0/24'];
  }
  if (operator === 'BETWEEN') {
    if (meta?.options && meta.options.length > 0) {
      return [meta.options[0]!.value, meta.options[meta.options.length - 1]!.value];
    }
    if (meta?.type === 'NUMBER') {
      return [0, typeof meta.defaultValue === 'number' ? meta.defaultValue : 100];
    }
    if (meta?.type === 'DATE') {
      return ['2026-01-01T00:00:00.000Z', '2026-12-31T23:59:59.000Z'];
    }
    return ['', ''];
  }
  if (operator === 'IN' || operator === 'NOT_IN') {
    if (meta?.type === 'IP') return ['192.168.1.1'];
    if (meta?.type === 'DATE') return ['2026-01-01T00:00:00.000Z'];
    if (Array.isArray(meta?.defaultValue)) return [...meta.defaultValue];
    if (meta?.defaultValue !== undefined && typeof meta.defaultValue !== 'object') {
      return [meta.defaultValue];
    }
    return [];
  }
  if (operator === 'EXISTS') return true;
  if (meta?.type === 'DATE') return '2026-01-01T00:00:00.000Z';
  if (meta?.type === 'IP') return '192.168.1.1';
  if (Array.isArray(meta?.defaultValue)) return String(meta.defaultValue[0] ?? '');
  return meta && typeof meta.defaultValue !== 'object' ? meta.defaultValue : '';
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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isValidExpectedScalar(value: unknown): value is string | number | boolean {
  if (typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  return false;
}

function isValidExpectedValue(value: unknown): value is ExpectedValue {
  if (isValidExpectedScalar(value)) return true;
  if (Array.isArray(value)) {
    return value.every((item) => isValidExpectedScalar(item));
  }
  if (isPlainObject(value)) {
    return (
      typeof value['start'] === 'string' &&
      typeof value['end'] === 'string' &&
      typeof value['timeZone'] === 'string'
    );
  }
  return false;
}

function parseObligationsFromJson(raw: unknown): VisualObligation[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new Error('Cấu trúc JSON không hợp lệ: trường "obligations" phải là một mảng.');
  }
  const parsed: VisualObligation[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') {
      const code = entry.trim();
      if (!VALID_SIMPLE_OBLIGATIONS.has(code)) {
        throw new Error(`Cấu trúc JSON không hợp lệ: loại nghĩa vụ "${code}" không được hỗ trợ.`);
      }
      parsed.push({ type: code } as VisualObligation);
      continue;
    }
    if (!isPlainObject(entry) || typeof entry['type'] !== 'string') {
      throw new Error('Cấu trúc JSON không hợp lệ: mỗi nghĩa vụ phải có trường "type" hợp lệ.');
    }
    const type = entry['type'].trim();
    if (type === 'MAX_SESSION_MINUTES') {
      const minutes = entry['minutes'];
      if (
        typeof minutes !== 'number' ||
        !Number.isInteger(minutes) ||
        minutes < MIN_SESSION_MINUTES ||
        minutes > MAX_SESSION_MINUTES
      ) {
        throw new Error(
          `Cấu trúc JSON không hợp lệ: nghĩa vụ "MAX_SESSION_MINUTES" yêu cầu "minutes" là số nguyên từ ${MIN_SESSION_MINUTES} đến ${MAX_SESSION_MINUTES}.`,
        );
      }
      parsed.push({ type: 'MAX_SESSION_MINUTES', minutes });
    } else if (VALID_SIMPLE_OBLIGATIONS.has(type)) {
      parsed.push({ type } as VisualObligation);
    } else {
      throw new Error(`Cấu trúc JSON không hợp lệ: loại nghĩa vụ "${type}" không được hỗ trợ.`);
    }
  }
  return parsed;
}

export function deserializePolicyAst(jsonText: string): VisualPolicyRule {
  let raw: unknown;
  try {
    raw = JSON.parse(jsonText);
  } catch {
    throw new Error(
      'Cú pháp JSON không hợp lệ. Vui lòng kiểm tra lại dấu ngoặc, dấu phẩy và chuỗi ký tự.',
    );
  }
  if (!isPlainObject(raw)) {
    throw new Error('Cấu trúc JSON không hợp lệ: gốc chính sách phải là một đối tượng JSON.');
  }

  const code = typeof raw['code'] === 'string' ? raw['code'].trim() : '';
  if (code.length < 2 || code.length > 80) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "code" bắt buộc là chuỗi từ 2 đến 80 ký tự.',
    );
  }

  const name = typeof raw['name'] === 'string' ? raw['name'].trim() : '';
  if (name.length < 2 || name.length > 180) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "name" bắt buộc là chuỗi từ 2 đến 180 ký tự.',
    );
  }

  if (
    raw['description'] !== undefined &&
    raw['description'] !== null &&
    (typeof raw['description'] !== 'string' || raw['description'].length > 2000)
  ) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "description" phải là chuỗi tối đa 2000 ký tự.',
    );
  }
  const description = typeof raw['description'] === 'string' ? raw['description'] : '';

  const effect = raw['effect'];
  if (effect !== 'PERMIT' && effect !== 'DENY') {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "effect" chỉ chấp nhận "PERMIT" hoặc "DENY".',
    );
  }

  const priority = raw['priority'];
  if (
    typeof priority !== 'number' ||
    !Number.isInteger(priority) ||
    priority < 1 ||
    priority > 100_000
  ) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "priority" phải là số nguyên từ 1 đến 100000.',
    );
  }

  if (raw['targetResource'] !== undefined && raw['targetResource'] !== 'DOCUMENT') {
    throw new Error('Cấu trúc JSON không hợp lệ: "targetResource" chỉ hỗ trợ "DOCUMENT".');
  }

  const rawAction = raw['targetAction'];
  if (
    rawAction !== undefined &&
    rawAction !== null &&
    (typeof rawAction !== 'string' || !VALID_TARGET_ACTIONS.has(rawAction as TargetAction))
  ) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: "targetAction" phải thuộc tập ALL, DISCOVER, VIEW, DOWNLOAD, SHARE hoặc MANAGE.',
    );
  }
  const targetAction: TargetAction =
    typeof rawAction === 'string' ? (rawAction as TargetAction) : 'ALL';

  if (raw['combiningAlgorithm'] !== undefined && raw['combiningAlgorithm'] !== 'DENY_OVERRIDES') {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: "combiningAlgorithm" chỉ hỗ trợ "DENY_OVERRIDES".',
    );
  }

  if (!Array.isArray(raw['groups']) || raw['groups'].length === 0) {
    throw new Error(
      'Cấu trúc JSON không hợp lệ: trường "groups" phải là mảng có ít nhất một nhóm điều kiện.',
    );
  }

  const groups: VisualConditionGroup[] = raw['groups'].map((rawGroup, groupIdx) => {
    if (!isPlainObject(rawGroup)) {
      throw new Error(
        `Cấu trúc JSON không hợp lệ: nhóm điều kiện thứ ${groupIdx + 1} sai định dạng.`,
      );
    }
    const groupId =
      typeof rawGroup['id'] === 'number' && Number.isInteger(rawGroup['id']) && rawGroup['id'] >= 1
        ? rawGroup['id']
        : groupIdx + 1;
    if (!Array.isArray(rawGroup['conditions']) || rawGroup['conditions'].length === 0) {
      throw new Error(
        `Cấu trúc JSON không hợp lệ: nhóm điều kiện #${groupId} phải có ít nhất một điều kiện.`,
      );
    }
    const conditions: VisualCondition[] = rawGroup['conditions'].map((rawCond, condIdx) => {
      if (!isPlainObject(rawCond)) {
        throw new Error(
          `Cấu trúc JSON không hợp lệ: điều kiện thứ ${condIdx + 1} trong nhóm #${groupId} sai định dạng.`,
        );
      }
      const attribute = typeof rawCond['attribute'] === 'string' ? rawCond['attribute'].trim() : '';
      if (!attribute) {
        throw new Error(
          `Cấu trúc JSON không hợp lệ: thiếu tên thuộc tính "attribute" trong nhóm #${groupId}.`,
        );
      }
      const operator = typeof rawCond['operator'] === 'string' ? rawCond['operator'].trim() : '';
      if (!POLICY_OPERATORS.includes(operator as PolicyOperator)) {
        throw new Error(
          `Cấu trúc JSON không hợp lệ: toán tử "${operator}" trong nhóm #${groupId} không được hỗ trợ.`,
        );
      }
      if (!isValidExpectedValue(rawCond['expected'])) {
        throw new Error(
          `Cấu trúc JSON không hợp lệ: giá trị "expected" của thuộc tính "${attribute}" không hợp lệ.`,
        );
      }
      const condId =
        typeof rawCond['id'] === 'string' && rawCond['id'].trim().length > 0
          ? rawCond['id'].trim()
          : createConditionId();
      return {
        id: condId,
        attribute,
        operator: operator as PolicyOperator,
        expected: rawCond['expected'],
      };
    });
    return { id: groupId, conditions };
  });

  const obligations = parseObligationsFromJson(raw['obligations']);
  const id =
    typeof raw['id'] === 'string' && raw['id'].trim().length > 0
      ? raw['id'].trim()
      : 'rule-new-001';

  return {
    id,
    code,
    name,
    description,
    effect,
    priority,
    targetResource: 'DOCUMENT',
    targetAction,
    combiningAlgorithm: 'DENY_OVERRIDES',
    ...(typeof raw['validFrom'] === 'string' ? { validFrom: raw['validFrom'] } : {}),
    ...(raw['validTo'] === null || typeof raw['validTo'] === 'string'
      ? { validTo: raw['validTo'] }
      : {}),
    groups,
    obligations,
  };
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
