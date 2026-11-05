export interface UserRow {
  id: string;
  username: string;
  fullName: string;
  email: string;
  status: string;
  departmentId: string | null;
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

export interface RoleRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  isSystemRole: boolean;
  isActive: boolean;
  version: number;
  permissions: Array<{ id?: string; code: string; name?: string }>;
}

export interface PermissionRow {
  id: string;
  code: string;
  resourceType: string;
  action: string;
  description?: string | null;
}

export interface AbacPolicyRow {
  id: string;
  name: string;
  description: string;
  effect: 'PERMIT' | 'DENY';
  isActive: boolean;
}

export interface AttributeOptionRow {
  id: string;
  code: string;
  name: string;
  numeric_rank?: number | null;
}

export interface AttributeDefinitionRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  data_type?: string | null;
  attribute_options: AttributeOptionRow[];
}

export interface WatermarkConfigRow {
  id: string;
  name: string;
  opacityPercent: number;
  rotationDegrees?: number;
  fontSize: number;
  colorHex?: string;
  includeQrCode: boolean;
  isDefault: boolean;
  isVisible: boolean;
  templateText?: string;
}

export interface SystemHealthData {
  status: string;
  database: { status: string; latencyMs?: number | undefined };
  cache: { status: string };
  uptimeSeconds: number;
}

export interface HealthReadyResponse {
  status: string;
  uptimeSeconds: number;
  checks: {
    database: { status: string; latencyMs?: number };
    redis?: { status: string };
  };
}

export type UserStatusAction = 'lock' | 'unlock' | 'disable';
