import type {
  ExpectedValue,
  PolicyOperator,
  TargetAction,
  VisualCondition,
  VisualConditionGroup,
  VisualObligation,
  VisualPolicyRule,
} from '@/components/abac/abac-models';
import { PRESET_POLICY_TEMPLATES } from '@/components/abac/policy-templates';
import type {
  AbacPolicyApiDto,
  AbacPolicyRow,
  AttributeDefinitionApiDto,
  AttributeDefinitionRow,
  PolicyRuleConditionDto,
} from './types';

const SIMPLE_OBLIGATION_TYPES = new Set([
  'REQUIRE_WATERMARK',
  'REQUIRE_MFA',
  'FORBID_DOWNLOAD',
  'NO_CACHE',
]);

/**
 * Thuật toán: Chuẩn Hóa Mảng Nghĩa Vụ ABAC Từ Dạng Chuỗi Hạt Giống Hoặc Đối Tượng Sang `VisualObligation[]` (`normalizeVisualObligations`)
 * Mục đích: Đảm bảo các luật mặc định lưu `["NO_CACHE"]` hay `["REQUIRE_WATERMARK", "NO_CACHE"]` hiển thị đúng dấu tick trong Trình dựng trực quan và luôn vượt qua lược đồ `PUT /abac/policies/:id`.
 */
export function normalizeVisualObligations(raw: unknown): VisualObligation[] {
  if (!Array.isArray(raw)) return [];
  const normalized: VisualObligation[] = [];
  for (const item of raw) {
    if (typeof item === 'string') {
      const code = item.trim();
      if (SIMPLE_OBLIGATION_TYPES.has(code)) {
        normalized.push({ type: code } as VisualObligation);
      }
      continue;
    }
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const rec = item as Record<string, unknown>;
      const type = typeof rec['type'] === 'string' ? rec['type'].trim() : '';
      if (type === 'MAX_SESSION_MINUTES') {
        const minutes = Number(rec['minutes']);
        normalized.push({
          type: 'MAX_SESSION_MINUTES',
          minutes: Number.isFinite(minutes) && minutes >= 1 ? Math.round(minutes) : 30,
        });
      } else if (SIMPLE_OBLIGATION_TYPES.has(type)) {
        normalized.push({ type } as VisualObligation);
      }
    }
  }
  return normalized;
}

/**
 * Thuật toán: Chuẩn Hóa Dữ Liệu Chính Sách & Định Nghĩa Thuộc Tính ABAC Giữa Snake_Case và CamelCase (`normalizeAbacPolicyRow` & `normalizeAttributeDefinitionRow`)
 * Mục đích: Đồng bộ nhất quán phản hồi REST API của máy chủ PDP sang lược đồ hiển thị trên bảng quản trị ABAC.
 */
export function normalizeAbacPolicyRow(raw: AbacPolicyApiDto): AbacPolicyRow {
  const rawAction = (raw.targetAction ?? raw.target_action ?? 'ALL').toUpperCase() as TargetAction;
  const rawObligations =
    raw.obligations !== undefined ? normalizeVisualObligations(raw.obligations) : undefined;

  return {
    id: String(raw.id),
    code: raw.code,
    name: raw.name,
    description: raw.description ?? '',
    effect: raw.effect,
    priority: raw.priority,
    targetAction: rawAction,
    isActive: Boolean(raw.isActive ?? raw.is_active),
    obligations: rawObligations,
    groups: raw.groups,
    policy_rule_conditions: raw.policy_rule_conditions,
  };
}

export function normalizeAttributeDefinitionRow(
  raw: AttributeDefinitionApiDto,
): AttributeDefinitionRow {
  return {
    id: String(raw.id),
    code: raw.code,
    name: raw.name,
    description: raw.description ?? null,
    data_type: raw.value_type ?? raw.data_type ?? 'STRING',
    attribute_options: (raw.attribute_options ?? []).map((opt) => ({
      id: String(opt.id),
      code: opt.value_code ?? opt.code ?? '',
      name: opt.display_name ?? opt.name ?? opt.value_code ?? opt.code ?? '',
      numeric_rank: opt.numeric_rank ?? null,
    })),
  };
}

const DEFINITION_CODE_TO_CONTEXT_KEY: Record<string, string> = {
  CLEARANCE_LEVEL: 'subject.clearanceRank',
  DEPARTMENT: 'subject.departmentId',
  SUBJECT_DEPARTMENT: 'subject.departmentId',
  EMPLOYMENT_STATUS: 'subject.employmentStatus',
  PROJECT: 'subject.projects',
  CLASSIFICATION_LEVEL: 'resource.classificationRank',
  RESOURCE_DEPARTMENT: 'resource.departmentId',
  CATEGORY: 'resource.category',
  RESOURCE_CATEGORY: 'resource.category',
};

function mapStoredConditionsToGroups(conditions: PolicyRuleConditionDto[]): VisualConditionGroup[] {
  const grouped = new Map<number, VisualCondition[]>();
  conditions.forEach((cond, idx) => {
    const groupNo = cond.condition_group ?? 1;
    const defCode = cond.attribute_definitions?.code ?? '';
    const attrKey =
      cond.context_key ||
      cond.attribute ||
      DEFINITION_CODE_TO_CONTEXT_KEY[defCode] ||
      'subject.clearanceRank';
    const item: VisualCondition = {
      id: cond.id !== undefined ? `cond-${cond.id}` : `cond-${idx + 1}`,
      attribute: attrKey,
      operator: (cond.operator || 'EQ') as PolicyOperator,
      expected: (cond.expected_value ?? cond.expected ?? '') as ExpectedValue,
    };
    const bucket = grouped.get(groupNo) ?? [];
    bucket.push(item);
    grouped.set(groupNo, bucket);
  });
  return Array.from(grouped.entries())
    .sort(([a], [b]) => a - b)
    .map(([id, groupConditions]) => ({ id, conditions: groupConditions }));
}

/**
 * Thuật toán: Tái Dựng Cây Điều Kiện DNF Thực Tế Từ CSDL Cho Trình Biên Tập Trực Quan (`resolveVisualRuleForPolicy`)
 * Cơ chế hoạt động: Ưu tiên dựng lại các nhóm liên hội/tuyển từ `groups` hoặc `policy_rule_conditions` thực tế do máy chủ trả về; chỉ đối chiếu mẫu dựng sẵn khi bản ghi chưa có điều kiện chi tiết.
 */
export function resolveVisualRuleForPolicy(p: AbacPolicyRow): VisualPolicyRule {
  const baseCode =
    p.code ||
    `POL_${p.name
      .toUpperCase()
      .replace(/[^A-Z0-9]+/gu, '_')
      .slice(0, 24)}`;
  const normalizedObligations = normalizeVisualObligations(p.obligations);

  if (p.groups && p.groups.length > 0) {
    return {
      id: p.id,
      code: baseCode,
      name: p.name,
      description: p.description,
      effect: p.effect,
      priority: p.priority ?? 10,
      targetResource: 'DOCUMENT',
      targetAction: p.targetAction ?? 'ALL',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: p.groups,
      obligations: normalizedObligations,
    };
  }

  if (p.policy_rule_conditions && p.policy_rule_conditions.length > 0) {
    return {
      id: p.id,
      code: baseCode,
      name: p.name,
      description: p.description,
      effect: p.effect,
      priority: p.priority ?? 10,
      targetResource: 'DOCUMENT',
      targetAction: p.targetAction ?? 'ALL',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: mapStoredConditionsToGroups(p.policy_rule_conditions),
      obligations: normalizedObligations,
    };
  }

  const matchedTemplate = PRESET_POLICY_TEMPLATES.find(
    (t) =>
      t.rule.code === p.code ||
      t.rule.name.toLowerCase().includes(p.name.toLowerCase()) ||
      p.name.toLowerCase().includes(t.rule.name.toLowerCase()),
  );
  if (matchedTemplate) {
    return { ...matchedTemplate.rule, id: p.id, code: baseCode, name: p.name, effect: p.effect };
  }

  return {
    id: p.id,
    code: baseCode,
    name: p.name,
    description: p.description,
    effect: p.effect,
    priority: p.priority ?? 10,
    targetResource: 'DOCUMENT',
    targetAction: p.targetAction ?? 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [],
    obligations: normalizedObligations,
  };
}
