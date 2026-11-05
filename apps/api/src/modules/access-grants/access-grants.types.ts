/**
 * @module AccessGrantsTypes
 * Algorithm: Canonical BigInt-Safe Serialization & DTO Contracts for Time-Bound Access Grants.
 */

export interface GrantDetail {
  id: string;
  documentId: string;
  principalType: string;
  principalUserId: string | null;
  principalRoleId: string | null;
  source: string;
  accessRequestId: string | null;
  permissions: string[];
  validFrom: string;
  validUntil: string;
  status: string;
  grantedBy: string;
  grantedAt: string;
  revokedBy: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  version: number;
  // CONFLICT-RESOLVED: Bổ sung trường quan hệ tùy chọn cho danh sách grant trên UI mà vẫn tương thích mock đơn vị
  document?: { title: string; documentCode: string };
  principalUser?: { fullName: string; username: string };
  principalRole?: { name: string; code: string };
}

export interface GrantListResult {
  data: GrantDetail[];
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface RawGrantRecord {
  id: string;
  document_id: string;
  principal_type: string;
  principal_user_id: bigint | null;
  principal_role_id: bigint | null;
  source: string;
  access_request_id: string | null;
  valid_from: Date;
  valid_until: Date;
  status: string;
  granted_by: bigint;
  granted_at: Date;
  revoked_by: bigint | null;
  revoked_at: Date | null;
  revoke_reason: string | null;
  version: number;
  access_grant_permissions: Array<{ permission: string }>;
  documents?: {
    title?: string;
    document_code?: string;
    department_id?: bigint;
    owner_id?: bigint;
  } | null;
  users_access_grants_principal_user_idTousers?: { full_name?: string; username?: string } | null;
  roles?: { name?: string; code?: string } | null;
}

/**
 * Algorithm / Thuật toán: Ánh xạ bản ghi `access_grants` sang DTO `GrantDetail` chuẩn hóa chuỗi ISO-8601 và ID 64-bit.
 */
export function toGrantDetail(grant: RawGrantRecord): GrantDetail {
  const docRel = grant.documents;
  const userRel = grant.users_access_grants_principal_user_idTousers;
  const roleRel = grant.roles;
  return {
    id: grant.id,
    documentId: grant.document_id,
    principalType: grant.principal_type,
    principalUserId: grant.principal_user_id?.toString() ?? null,
    principalRoleId: grant.principal_role_id?.toString() ?? null,
    source: grant.source,
    accessRequestId: grant.access_request_id,
    permissions: grant.access_grant_permissions.map((p) => p.permission),
    validFrom: grant.valid_from.toISOString(),
    validUntil: grant.valid_until.toISOString(),
    status: grant.status,
    grantedBy: grant.granted_by.toString(),
    grantedAt: grant.granted_at.toISOString(),
    revokedBy: grant.revoked_by?.toString() ?? null,
    revokedAt: grant.revoked_at?.toISOString() ?? null,
    revokeReason: grant.revoke_reason,
    version: grant.version,
    ...(docRel?.title !== undefined && docRel?.document_code !== undefined
      ? { document: { title: docRel.title, documentCode: docRel.document_code } }
      : {}),
    ...(userRel?.full_name !== undefined && userRel?.username !== undefined
      ? { principalUser: { fullName: userRel.full_name, username: userRel.username } }
      : {}),
    ...(roleRel?.name !== undefined && roleRel?.code !== undefined
      ? { principalRole: { name: roleRel.name, code: roleRel.code } }
      : {}),
  };
}
