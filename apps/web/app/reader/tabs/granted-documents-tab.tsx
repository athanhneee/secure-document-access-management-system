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
import type { MyGrantedDoc } from '../types';

interface GrantedDocumentsTabProps {
  myDocs: MyGrantedDoc[];
  downloadingDocId: string | null;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onDownload: (doc: MyGrantedDoc) => void;
}

export function GrantedDocumentsTab({
  myDocs,
  downloadingDocId,
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
              <TableHead className="text-xs text-[#717171] text-right">Xem &amp; Tải</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {myDocs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                  Bạn chưa có giấy phép truy cập nào còn hiệu lực
                </TableCell>
              </TableRow>
            ) : (
              myDocs.map((doc) => {
                const canDownload = doc.permissions.includes('DOWNLOAD') && doc.allowDownload;
                const isDownloading = downloadingDocId === doc.documentId;

                return (
                  <TableRow
                    key={doc.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell>
                      <div className="font-semibold text-xs text-[#222222]">{doc.title}</div>
                      <div className="text-xs font-bold text-[#717171]">
                        {doc.documentCode || 'DOC-' + doc.id.slice(0, 8)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <ClassificationBadge level={doc.classificationCode} showRank />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-3">
                        {doc.permissions.map((p) => (
                          <Badge key={p} variant="secondary">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs font-bold text-[#222222]">
                      <span className="inline-flex items-center gap-1.5">
                        <span className="dot dot-warning" aria-hidden="true" />
                        <span>{new Date(doc.validUntil).toLocaleDateString('vi-VN')}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        <InteractiveHoverButton
                          size="sm"
                          variant="primary"
                          text="Xem"
                          icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onOpenPreview(doc)}
                        />

                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Tải bản sao"
                          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                          disabled={!canDownload || isDownloading}
                          isLoading={isDownloading}
                          onClick={() => onDownload(doc)}
                          title={
                            !canDownload
                              ? 'Chính sách mức mật hoặc giấy phép không cho phép tải về'
                              : 'Tải bản sao có watermark bảo mật'
                          }
                        />
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
