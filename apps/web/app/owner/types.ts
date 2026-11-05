import type { ClassificationCode } from '@/components/classification-badge';

export interface DocumentItem {
  id: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  classificationRank?: number | undefined;
  classificationLevelId?: number | undefined;
  businessCategoryId?: number | undefined;
  businessCategoryName?: string | undefined;
  status: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  departmentId?: number | undefined;
  departmentName?: string | undefined;
  allowDownload: boolean;
  versionCount?: number | undefined;
  createdAt: string;
}

export interface DocumentApiDto {
  id: string;
  title?: string;
  documentCode?: string;
  document_code?: string;
  // CONFLICT-RESOLVED: Bổ sung trường phẳng classificationLevelCode, classificationLevelName, departmentName từ GET /api/v1/documents.
  classificationLevelCode?: ClassificationCode | null;
  classificationLevelName?: string | null;
  classificationCode?: ClassificationCode;
  classification?: {
    id?: number;
    code?: ClassificationCode;
    rank?: number;
    allowDownload?: boolean;
  };
  classification_level_id?: number;
  business_category_id?: number;
  businessCategoryName?: string | null;
  businessCategory?: { id?: number; name?: string };
  business_categories?: { id?: number; name?: string };
  status?: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  department_id?: number;
  departmentName?: string | null;
  department?: { id?: number; name?: string };
  departments?: { id?: number; name?: string };
  allowDownload?: boolean;
  versions?: unknown[];
  createdAt?: string;
  created_at?: string;
}

export interface AccessGrantApiDto {
  id: string;
  documentId: string;
  document?: { title?: string };
  // CONFLICT-RESOLVED: Bổ sung principalUserId và principalRoleId khớp GrantDetail trả về từ GET /api/v1/access-grants.
  principalType?: 'USER' | 'ROLE' | string;
  principalUserId?: string | number | null;
  principalRoleId?: string | number | null;
  principalUser?: { fullName?: string; username?: string };
  principalRole?: { name?: string; code?: string };
  permissions?: string[];
  validFrom?: string;
  validUntil?: string;
  status?: 'ACTIVE' | 'REVOKED' | 'EXPIRED' | string;
  version?: number;
}

export interface GrantLookupMaps {
  docsById?: ReadonlyMap<string, Pick<DocumentItem, 'title'>>;
  usersById?: ReadonlyMap<string, Pick<UserLookupItem, 'fullName' | 'username'>>;
  rolesById?: ReadonlyMap<string, Pick<RoleLookupItem, 'name' | 'code'>>;
}

export interface AccessRequestItem {
  id: string;
  documentId: string;
  documentTitle: string;
  requestorName: string;
  requestorDepartment: string;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  requestedFrom?: string;
  requestedUntil?: string;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  createdAt: string;
}

export interface AccessGrantItem {
  id: string;
  documentId: string;
  documentTitle: string;
  principalType: 'USER' | 'ROLE';
  principalName: string;
  permissions: string[];
  validFrom: string;
  validUntil: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  version: number;
}

export interface DepartmentLookupItem {
  id: number;
  code: string;
  name: string;
}

export interface BusinessCategoryLookupItem {
  id: number;
  code: string;
  name: string;
  departmentId: number | null;
}

export interface ClassificationLevelLookupItem {
  id: number;
  code: ClassificationCode;
  name: string;
  rank: number;
  allowDownload: boolean;
  requireWatermark: boolean;
  defaultViewDays?: number;
}

export interface UserLookupItem {
  id: string;
  username: string;
  fullName: string;
  departmentName: string;
  clearanceRank: number;
}

export interface RoleLookupItem {
  id: string;
  code: string;
  name: string;
}

export interface AuditLogItem {
  id: string;
  occurredAt: string;
  actorUserId: string | null;
  actorUsername: string | null;
  action: string;
  objectType: string;
  objectId: string | null;
  documentId: string | null;
  accessSessionId: string | null;
  outcome: string;
  reasonCode: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  details: Record<string, unknown> | null;
  entryHash: string;
  chainSequence: string;
}

export interface DocumentVersionItem {
  id: string;
  versionNo: number;
  originalFilename: string;
  mimeType: string;
  fileSizeBytes: string;
  sha256Hash: string;
  scanStatus: string;
  changeNote: string | null;
  uploadedBy: string;
  createdAt: string;
}

export interface ClassificationHistoryItem {
  id: string;
  classificationLevelCode: string;
  classificationLevelName: string;
  rank: number;
  businessCategoryCode: string;
  businessCategoryName: string;
  reason: string | null;
  classifiedBy: string;
  effectiveFrom: string;
  effectiveTo: string | null;
}
