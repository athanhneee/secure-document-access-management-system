import type {
  TargetAction,
  VisualConditionGroup,
  VisualObligation,
} from '@/components/abac/abac-models';

export interface ClearanceOptionRow {
  id: string;
  code: string;
  name: string;
  rank: number;
}

export interface UserRow {
  id: string;
  username: string;
  fullName: string;
  email: string;
  employeeCode?: string | null | undefined;
  status: string;
  departmentId: string | null;
  clearanceOptionId?: string | null | undefined;
  clearanceCode?: string | null | undefined;
  clearanceName?: string | null | undefined;
  clearanceRank?: number | undefined;
  version: number;
}

export interface DepartmentRow {
  id: string;
  code: string;
  name: string;
  parentId: string | null;
  isActive: boolean;
  version: number;
}

export interface DepartmentLookupRow {
  id: string;
  code: string;
  name: string;
}

export interface BusinessCategoryOptionRow {
  id: string;
  code: string;
  name: string;
  departmentId?: string | null;
  departmentName?: string | null;
}

export interface UserRoleAssignmentRow {
  id: string;
  roleId: string;
  roleCode: string;
  roleName?: string | undefined;
  roleIsActive?: boolean | undefined;
  scopeDepartmentId: string | null;
  validFrom: string;
  validTo: string | null;
}

export interface RoleRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  isSystemRole: boolean;
  isActive: boolean;
  version: number;
  permissions: Array<{
    id?: string;
    code: string;
    name?: string | null | undefined;
    resource?: string | undefined;
    action?: string | undefined;
  }>;
}

export interface PermissionRow {
  id: string;
  code: string;
  name?: string | null | undefined;
  resource?: string | undefined;
  resourceType?: string | undefined;
  action: string;
  description?: string | null;
}

export interface PolicyRuleConditionDto {
  id?: string | number;
  condition_group?: number;
  sequence_no?: number;
  context_key?: string | null;
  attribute?: string;
  operator?: string;
  expected_value?: unknown;
  expected?: unknown;
  attribute_definitions?: { code?: string | null } | null;
}

export interface AbacPolicyApiDto {
  id: string | number;
  code?: string;
  name: string;
  description?: string | null;
  effect: 'PERMIT' | 'DENY';
  priority?: number;
  targetResource?: string;
  target_resource?: string;
  targetAction?: string;
  target_action?: string;
  isActive?: boolean;
  is_active?: boolean;
  obligations?: unknown;
  groups?: VisualConditionGroup[];
  policy_rule_conditions?: PolicyRuleConditionDto[];
}

export interface AbacPolicyRow {
  id: string;
  code?: string | undefined;
  name: string;
  description: string;
  effect: 'PERMIT' | 'DENY';
  priority?: number | undefined;
  targetAction?: TargetAction | undefined;
  isActive: boolean;
  obligations?: VisualObligation[] | undefined;
  groups?: VisualConditionGroup[] | undefined;
  policy_rule_conditions?: PolicyRuleConditionDto[] | undefined;
}

interface AttributeOptionApiDto {
  id: string | number;
  code?: string;
  value_code?: string;
  name?: string;
  display_name?: string;
  numeric_rank?: number | null;
}

interface AttributeOptionRow {
  id: string;
  code: string;
  name: string;
  numeric_rank?: number | null;
}

export interface AttributeDefinitionApiDto {
  id: string | number;
  code: string;
  name: string;
  description?: string | null;
  data_type?: string | null;
  value_type?: string | null;
  attribute_options?: AttributeOptionApiDto[];
}

export interface AttributeDefinitionRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  data_type: string;
  attribute_options: AttributeOptionRow[];
}

export interface WatermarkConfigRow {
  id: string;
  name: string;
  classificationLevelId?: string | null | undefined;
  classificationLevel?:
    | {
        id: number;
        code: string;
        name: string;
        rank: number;
      }
    | null
    | undefined;
  opacityPercent: number;
  rotationDegrees?: number;
  fontSize: number;
  colorHex?: string;
  includeQrCode: boolean;
  isDefault: boolean;
  isVisible: boolean;
  templateText?: string;
}

export type HealthStatusLabel = 'ONLINE' | 'DEGRADED' | 'OFFLINE';

export interface SystemHealthData {
  status: HealthStatusLabel;
  database: { status: HealthStatusLabel; latencyMs?: number | undefined };
  cache: { status: HealthStatusLabel; latencyMs?: number | undefined };
  storage: { status: HealthStatusLabel; latencyMs?: number | undefined };
  uptimeSeconds: number;
  memory?:
    | {
        heapUsedMb?: number | undefined;
        heapTotalMb?: number | undefined;
        rssMb?: number | undefined;
      }
    | undefined;
}

export interface HealthReadyResponse {
  status?: string;
  uptimeSeconds?: number;
  checks?: {
    database?: { status?: string; latencyMs?: number };
    redis?: { status?: string; latencyMs?: number };
    storage?: { status?: string; latencyMs?: number };
  };
}

export interface HealthDashboardResponse {
  process?: {
    uptimeSeconds?: number;
    heapUsedMb?: number;
    heapTotalMb?: number;
    rssMb?: number;
  };
  operational?: {
    activeSessionsCount?: number;
    openAlertsCount?: number;
    pendingExportsCount?: number;
  };
  dependencies?: {
    isReady?: boolean;
    checks?: HealthReadyResponse['checks'];
  };
}

export type UserStatusAction = 'lock' | 'unlock' | 'disable' | 'reactivate';

export type AdminTab = 'users' | 'departments' | 'rbac' | 'abac' | 'watermark' | 'health';
