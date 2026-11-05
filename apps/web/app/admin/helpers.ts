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
  DepartmentRow,
  HealthDashboardResponse,
  HealthReadyResponse,
  HealthStatusLabel,
  PermissionRow,
  PolicyRuleConditionDto,
  RoleRow,
  SystemHealthData,
  UserRow,
} from './types';

/**
 * Thuật toán: Tìm kiếm Định danh Người dùng Đa Trường Không Phân biệt Hoa Thường (`filterUsersByQuery`)
 * Mục đích: Lọc tức thời danh sách tài khoản theo chuỗi con khớp trên họ tên, tên đăng nhập hoặc thư điện tử.
 * Cơ chế hoạt động: Chuẩn hóa từ khóa về chữ thường một lần và duyệt tuyến tính `O(N)`.
 */
export function filterUsersByQuery(users: UserRow[], searchQuery: string): UserRow[] {
  const query = searchQuery.toLowerCase();
  return users.filter(
    (u) =>
      u.fullName.toLowerCase().includes(query) ||
      u.username.toLowerCase().includes(query) ||
      u.email.toLowerCase().includes(query),
  );
}

/**
 * Thuật toán: Tra Cứu Nhãn Đơn Vị Cấp Cha Trên Cây Tổ Chức (`resolveParentDepartmentLabel`)
 * Cơ chế hoạt động: Duyệt danh sách kề phẳng tìm tên phòng ban cha hoặc gán nhãn gốc `'Trụ sở chính'`.
 */
export function resolveParentDepartmentLabel(
  departments: DepartmentRow[],
  parentId: string | null,
): string {
  if (!parentId) return 'Trụ sở chính';
  return departments.find((d) => d.id === parentId)?.name || parentId;
}

/**
 * Thuật toán: Định Dạng Mốc Thời Gian Cục Bộ ISO-8601 & Khung Hiệu Lực Vai Trò 30 Ngày (`formatLocalDateTimeInput`)
 */
export function formatLocalDateTimeInput(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function getDefaultRoleAssignmentWindow(): { validFrom: string; validTo: string } {
  const now = new Date();
  const nextMonth = new Date(Date.now() + 30 * 86400000);
  return {
    validFrom: formatLocalDateTimeInput(now),
    validTo: formatLocalDateTimeInput(nextMonth),
  };
}

/**
 * Thuật toán: Chuẩn Hóa Trạng Thái Thăm Dò Sức Khỏe Hạ Tầng Không Phân Biệt Hoa Thường (`normalizeProbeStatus` & `mapHealthReadyResponse`)
 * Mục đích: Ánh xạ trung thực phản hồi `/health/ready` (kể cả mã 503 chữ thường `'ready'`/`'up'`/`'degraded'`/`'down'`) và `/health/dashboard` sang miền trạng thái giao diện `ONLINE | DEGRADED | OFFLINE` mà không bịa số liệu giả.
 */
export function normalizeProbeStatus(
  raw: string | undefined,
  fallback: HealthStatusLabel = 'OFFLINE',
): HealthStatusLabel {
  const upper = raw?.trim().toUpperCase();
  if (
    upper === 'READY' ||
    upper === 'UP' ||
    upper === 'ONLINE' ||
    upper === 'OK' ||
    upper === 'HEALTHY'
  ) {
    return 'ONLINE';
  }
  if (upper === 'DEGRADED') return 'DEGRADED';
  if (upper === 'DOWN' || upper === 'OFFLINE' || upper === 'ERROR' || upper === 'UNHEALTHY') {
    return 'OFFLINE';
  }
  return fallback;
}

export function mapHealthReadyResponse(
  ready?: HealthReadyResponse | null,
  dashboard?: HealthDashboardResponse | null,
): SystemHealthData {
  // CONFLICT-RESOLVED: Chuẩn hóa không phân biệt hoa thường cho cả phản hồi 200 lẫn 503 và lấy uptime thực từ /health/dashboard thay vì mặc định giả lập ONLINE.
  const checks = ready?.checks ?? dashboard?.dependencies?.checks;
  const overallStatus: HealthStatusLabel = ready?.status
    ? normalizeProbeStatus(ready.status, 'OFFLINE')
    : dashboard?.dependencies?.isReady !== undefined
      ? dashboard.dependencies.isReady
        ? 'ONLINE'
        : 'DEGRADED'
      : 'OFFLINE';

  return {
    status: overallStatus,
    database: {
      status: normalizeProbeStatus(checks?.database?.status, 'OFFLINE'),
      ...(checks?.database?.latencyMs !== undefined
        ? { latencyMs: checks.database.latencyMs }
        : {}),
    },
    cache: {
      status: normalizeProbeStatus(checks?.redis?.status, 'OFFLINE'),
    },
    uptimeSeconds: dashboard?.process?.uptimeSeconds ?? ready?.uptimeSeconds ?? 0,
  };
}

/**
 * Thuật toán: Giao Tập Mã Quyền Vai Trò Sang Danh Sách Định Danh Danh Mục (`resolveRolePermissionIds`)
 */
export function resolveRolePermissionIds(role: RoleRow, permissions: PermissionRow[]): string[] {
  const currentPermCodes = role.permissions.map((p) => p.code);
  return permissions.filter((p) => currentPermCodes.includes(p.code)).map((p) => p.id);
}

/**
 * Thuật toán: Chuẩn Hóa Dữ Liệu Chính Sách & Định Nghĩa Thuộc Tính ABAC Giữa Snake_Case và CamelCase (`normalizeAbacPolicyRow` & `normalizeAttributeDefinitionRow`)
 */
export function normalizeAbacPolicyRow(raw: AbacPolicyApiDto): AbacPolicyRow {
  const rawAction = (raw.targetAction ?? raw.target_action ?? 'ALL').toUpperCase() as TargetAction;
  const rawObligations = Array.isArray(raw.obligations)
    ? (raw.obligations as VisualObligation[])
    : undefined;

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
  PROJECT: 'subject.projects',
  CLASSIFICATION_LEVEL: 'resource.classificationRank',
  CATEGORY: 'resource.category',
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
  // CONFLICT-RESOLVED: Phục dựng điều kiện thực tế từ policy_rule_conditions của backend thay vì bịa đặt điều kiện giả lập cố định.
  const baseCode =
    p.code ||
    `POL_${p.name
      .toUpperCase()
      .replace(/[^A-Z0-9]+/gu, '_')
      .slice(0, 24)}`;

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
      obligations: p.obligations ?? [],
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
      obligations: p.obligations ?? [],
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
    obligations: p.obligations ?? [],
  };
}
