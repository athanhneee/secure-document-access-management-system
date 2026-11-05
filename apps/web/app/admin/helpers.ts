import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { PRESET_POLICY_TEMPLATES } from '@/components/abac/policy-templates';
import type {
  AbacPolicyRow,
  DepartmentRow,
  HealthReadyResponse,
  PermissionRow,
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
 * Algorithm: Organizational Hierarchy Parent Lookup
 * Resolves parent department display label from flat adjacency list, defaulting root nodes to HQ.
 */
export function resolveParentDepartmentLabel(
  departments: DepartmentRow[],
  parentId: string | null,
): string {
  if (!parentId) return 'Trụ sở chính';
  return departments.find((d) => d.id === parentId)?.name || parentId;
}

/**
 * Algorithm: Local ISO-8601 Datetime-Local Input Formatting
 * Produces zero-padded YYYY-MM-DDTHH:mm strings and a default 30-day temporal RBAC validity window.
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
 * Algorithm: Health Readiness Probe Normalization
 * Maps raw /health/ready gateway probe checks into standardized UI status states.
 */
export function mapHealthReadyResponse(ready: HealthReadyResponse): SystemHealthData {
  return {
    status: ready.status === 'READY' ? 'ONLINE' : ready.status,
    database: {
      status: ready.checks?.database?.status === 'UP' ? 'ONLINE' : 'OFFLINE',
      ...(ready.checks?.database?.latencyMs !== undefined
        ? { latencyMs: ready.checks.database.latencyMs }
        : {}),
    },
    cache: {
      status: ready.checks?.redis?.status === 'UP' ? 'ONLINE' : 'DEGRADED',
    },
    uptimeSeconds: ready.uptimeSeconds ?? 0,
  };
}

/**
 * Algorithm: Role Permission Code-to-ID Matrix Synchronization
 * Intersects assigned role permission codes against master permission catalog IDs.
 */
export function resolveRolePermissionIds(role: RoleRow, permissions: PermissionRow[]): string[] {
  const currentPermCodes = role.permissions.map((p) => p.code);
  return permissions.filter((p) => currentPermCodes.includes(p.code)).map((p) => p.id);
}

/**
 * Algorithm: ABAC Policy Preset Matching & Visual AST Fallback Synthesis
 * Matches an existing PDP policy row against preset visual templates or synthesizes a default AST rule.
 */
export function resolveVisualRuleForPolicy(p: AbacPolicyRow): VisualPolicyRule {
  const matchedTemplate = PRESET_POLICY_TEMPLATES.find(
    (t) =>
      t.rule.name.toLowerCase().includes(p.name.toLowerCase()) ||
      p.name.toLowerCase().includes(t.rule.name.toLowerCase()),
  );
  if (matchedTemplate) {
    return matchedTemplate.rule;
  }
  return {
    id: p.id,
    code: `POL_${p.name.toUpperCase().replace(/\s+/g, '_').slice(0, 20)}`,
    name: p.name,
    description: p.description,
    effect: p.effect,
    priority: 10,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          {
            id: 'cond-auto-1',
            attribute: 'subject.clearanceRank',
            operator: 'GTE',
            expected: 2,
          },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_WATERMARK' }],
  };
}

/**
 * Algorithm: Local ABAC Draft Policy Upsert
 * Merges a newly edited visual rule into local policy state by ID or name without mutating active flags.
 */
export function upsertDraftPolicy(
  prev: AbacPolicyRow[],
  savedRule: VisualPolicyRule,
): AbacPolicyRow[] {
  const existing = prev.find((p) => p.name === savedRule.name || p.id === savedRule.id);
  if (existing) {
    return prev.map((p) =>
      p.id === existing.id
        ? {
            ...p,
            name: savedRule.name,
            description: savedRule.description,
            effect: savedRule.effect,
          }
        : p,
    );
  }
  return [
    ...prev,
    {
      id: savedRule.id,
      name: savedRule.name,
      description: savedRule.description,
      effect: savedRule.effect,
      isActive: false,
    },
  ];
}
