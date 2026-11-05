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
  classificationCode?: ClassificationCode;
  classification?: { code?: ClassificationCode; rank?: number };
  department?: { name?: string };
  allowDownload?: boolean;
}

export interface ReaderGrantApiDto {
  id?: string;
  documentId?: string;
  title?: string;
  documentCode?: string;
  classificationCode?: ClassificationCode;
  document?: { title?: string; documentCode?: string; classificationCode?: ClassificationCode };
  permissions?: ('VIEW' | 'DOWNLOAD')[];
  validUntil?: string;
  allowDownload?: boolean;
}
