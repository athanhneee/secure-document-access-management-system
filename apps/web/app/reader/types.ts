import type { ClassificationCode } from '@/components/classification-badge';

export interface DiscoverableDoc {
  id: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  classificationRank?: number | undefined;
  departmentName?: string | undefined;
  allowDownload: boolean;
  hasAccess?: boolean | undefined;
}

export interface MyGrantedDoc {
  id: string;
  documentId: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  permissions: Array<'VIEW' | 'DOWNLOAD'>;
  validUntil: string;
  allowDownload: boolean;
}

export interface MyRequestItem {
  id: string;
  documentTitle: string;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED';
  createdAt: string;
  requestedFrom?: string;
  requestedUntil?: string;
  reason?: string;
}

export interface ReaderDocumentApiDto {
  id: string;
  title?: string;
  documentCode?: string;
  document_code?: string;
  // CONFLICT-RESOLVED: Bổ sung các trường phẳng từ GET /api/v1/documents (classificationLevelCode, classificationLevelName, departmentName) song song cấu trúc lồng cũ.
  classificationLevelCode?: ClassificationCode | null;
  classificationLevelName?: string | null;
  classificationCode?: ClassificationCode;
  classification?: { code?: ClassificationCode; rank?: number; allowDownload?: boolean };
  departmentName?: string | null;
  department?: { name?: string };
  allowDownload?: boolean;
}

export interface ReaderGrantApiDto {
  // CONFLICT-RESOLVED: Đồng bộ cấu trúc trả về thực tế của GET /api/v1/documents/my-grants (grantId, grantStatus, validFrom, document lồng).
  grantId?: string;
  id?: string;
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
  };
}
