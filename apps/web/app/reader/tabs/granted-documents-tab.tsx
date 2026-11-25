'use client';

import { Eye, Download } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { formatPermissionActionLabel, formatSafeDateVi } from '@/lib/ui-labels';
import type { MyGrantedDoc } from '../types';

interface GrantedDocumentsTabProps {
  myDocs: MyGrantedDoc[];
  downloadingDocId: string | null;
  canViewDocument?: boolean;
  canDownloadDocument?: boolean;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onDownload: (doc: MyGrantedDoc) => void;
}

export function GrantedDocumentsTab({
  myDocs,
  downloadingDocId,
  canViewDocument = true,
  canDownloadDocument = true,
  onOpenPreview,
  onDownload,
}: GrantedDocumentsTabProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Tài liệu được cấp quyền ({myDocs.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
              <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
              <TableHead className="text-xs text-[#717171]">Quyền được cấp</TableHead>
              <TableHead className="text-xs text-[#717171]">Hiệu lực đến</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {myDocs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                  Bạn chưa có tài liệu nào được cấp quyền truy cập còn hiệu lực.
                </TableCell>
              </TableRow>
            ) : (
              myDocs.map((doc) => {
                const canDownload =
                  doc.permissions.includes('DOWNLOAD') && doc.allowDownload && canDownloadDocument;
                const isDownloading = downloadingDocId === doc.documentId;

                return (
                  <TableRow
                    key={doc.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell>
                      <div className="font-semibold text-xs text-[#222222]">{doc.title}</div>
                      <div className="text-xs font-bold text-[#717171]">
                        {doc.documentCode || 'Chưa cấp mã'}
                      </div>
                    </TableCell>
                    <TableCell>
                      <ClassificationBadge level={doc.classificationCode} />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-3">
                        {doc.permissions.map((p) => (
                          <Badge key={p} variant="secondary">
                            {formatPermissionActionLabel(p)}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs font-bold text-[#222222]">
                      <span className="inline-flex items-center gap-1.5">
                        <span className="dot dot-warning" aria-hidden="true" />
                        <span>{formatSafeDateVi(doc.validUntil)}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        {canViewDocument && (
                          <InteractiveHoverButton
                            size="sm"
                            variant="primary"
                            text="Xem tài liệu"
                            icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenPreview(doc)}
                          />
                        )}

                        {canDownload && (
                          <InteractiveHoverButton
                            size="sm"
                            variant="secondary"
                            text="Tải bản sao"
                            icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                            disabled={isDownloading}
                            isLoading={isDownloading}
                            onClick={() => onDownload(doc)}
                            title="Tải bản sao có watermark bảo mật"
                          />
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
