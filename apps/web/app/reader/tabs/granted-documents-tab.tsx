'use client';

import { Eye, Download } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
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
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Tài liệu đã được cấp quyền truy cập
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Giấy phép còn hiệu lực theo thời gian quy định; xem trực tuyến hoặc tải về kèm dấu bản
          quyền
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
                <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                <TableHead className="text-xs text-[#717171]">Quyền được cấp</TableHead>
                <TableHead className="text-xs text-[#717171]">Hiệu lực đến</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Xem & Tải</TableHead>
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
                        <div className="text-[11px] font-bold text-[#717171]">
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
                      {/* CONFLICT-RESOLVED: Chuẩn hóa màu hạn hiệu lực sang mã cảnh báo #E07912 trong bảng màu chính thức (rules/ui-design-system.md §5) */}
                      <TableCell className="text-xs font-bold text-[#E07912]">
                        {new Date(doc.validUntil).toLocaleDateString('vi-VN')}
                      </TableCell>
                      <TableCell className="text-right space-x-1">
                        <InteractiveHoverButton
                          size="sm"
                          variant="primary"
                          text="Xem Sandbox"
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
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
