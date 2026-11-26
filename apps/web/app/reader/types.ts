import type { ClassificationCode } from '@/components/classification-badge';

export interface DiscoverableDoc {
  id: string;
  title: string;
  documentCode?: string | undefined;
  description?: string | null | undefined;
  businessCategoryName?: string | null | undefined;
  classificationCode: ClassificationCode;
  classificationRank: number;
  departmentName?: string | undefined;
  allowDownload: boolean;
  retentionUntil?: string | null | undefined;
  defaultViewDays?: number | null | undefined;
}

export interface MyGrantedDoc {
  id: string;
  documentId: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  permissions: Array<'VIEW' | 'DOWNLOAD'>;
  principalType: 'USER' | 'ROLE';
  roleName?: string | null | undefined;
  hasDirectAndRoleGrant?: boolean | undefined;
  validFrom?: string | undefined;
  validUntil: string;
  grantedAt?: string | undefined;
  allowDownload: boolean;
  retentionUntil?: string | null | undefined;
  defaultViewDays?: number | null | undefined;
}

export interface MyRequestItem {
  id: string;
  documentId?: string | undefined;
  documentTitle: string;
  documentCode?: string | null | undefined;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'EXPIRED';
  createdAt: string;
  requestedFrom?: string | undefined;
  requestedUntil?: string | undefined;
  justification?: string | undefined;
  decidedAt?: string | null | undefined;
  decisionNote?: string | null | undefined;
}

export interface ReaderDocumentApiDto {
  id: string;
  title?: string;
  documentCode?: string;
  document_code?: string;
  description?: string | null;
  businessCategoryName?: string | null;
  // CONFLICT-RESOLVED: Bổ sung các trường phẳng từ GET /api/v1/documents (classificationLevelCode, classificationLevelName, departmentName) song song cấu trúc lồng cũ.
  classificationLevelCode?: ClassificationCode | null;
  classificationLevelName?: string | null;
  classificationCode?: ClassificationCode;
  classification?: { code?: ClassificationCode; rank?: number; allowDownload?: boolean };
  departmentName?: string | null;
  department?: { name?: string };
  allowDownload?: boolean;
  retentionUntil?: string | null;
  retention_until?: string | null;
  defaultViewDays?: number | null;
}

export interface ReaderGrantApiDto {
  // CONFLICT-RESOLVED: Đồng bộ cấu trúc trả về thực tế của GET /api/v1/documents/my-grants (grantId, principalType, roleName, grantStatus, validFrom, document lồng).
  grantId?: string;
  id?: string;
  principalType?: 'USER' | 'ROLE';
  roleName?: string | null;
  documentId?: string;
  title?: string;
  documentTitle?: string;
  documentCode?: string;
  classificationCode?: ClassificationCode;
  grantStatus?: string;
  status?: string;
  validFrom?: string;
  validUntil?: string;
  grantedAt?: string;
  permissions?: string[];
  allowDownload?: boolean;
  document?: {
    id?: string;
    documentCode?: string;
    title?: string;
    status?: string;
    classificationLevelName?: string | null;
    classificationLevelCode?: ClassificationCode | null;
    classificationCode?: ClassificationCode;
    allowDownload?: boolean;
    retentionUntil?: string | null;
    defaultViewDays?: number | null;
  };
}
