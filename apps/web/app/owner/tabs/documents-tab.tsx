'use client';

import {
  Search,
  Download,
  Eye,
  CheckCircle2,
  Layers,
  ShieldCheck,
  Archive,
  History,
} from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
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
import type { DocumentItem } from '../types';

interface DocumentsTabProps {
  documents: DocumentItem[];
  searchQuery: string;
  onSearchChange: (value: string) => void;
  isLoadingPreview: boolean;
  downloadingDocId: string | null;
  onActivate: (doc: DocumentItem) => void;
  onOpenPreview: (doc: DocumentItem) => void;
  onDownload: (doc: DocumentItem) => void;
  onOpenNewVersion: (doc: DocumentItem) => void;
  onOpenReclassify: (doc: DocumentItem) => void;
  onOpenArchive: (doc: DocumentItem) => void;
  onOpenVersionHistory: (doc: DocumentItem) => void;
}

export function DocumentsTab({
  documents,
  searchQuery,
  onSearchChange,
  isLoadingPreview,
  downloadingDocId,
  onActivate,
  onOpenPreview,
  onDownload,
  onOpenNewVersion,
  onOpenReclassify,
  onOpenArchive,
  onOpenVersionHistory,
}: DocumentsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222]">Kho tài liệu mật đang quản lý</CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Mỗi tài liệu bắt buộc gắn nhãn mức mật, phòng ban, danh mục nghiệp vụ và chính sách kiểm
            soát
          </CardDescription>
        </div>
        <div className="relative w-full sm:w-64">
          <Search
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3 top-2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            type="text"
            aria-label="Tìm kiếm tài liệu theo tiêu đề hoặc mã số"
            placeholder="Tìm theo tiêu đề, mã số..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-9 h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
                <TableHead className="text-xs text-[#717171]">Phòng ban &amp; Danh mục</TableHead>
                <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                <TableHead className="text-xs text-[#717171]">Phiên bản</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">
                  Thao tác &amp; Vòng đời
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {documents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-[#717171] text-xs">
                    Chưa có tài liệu nào trong danh mục quản lý
                  </TableCell>
                </TableRow>
              ) : (
                documents.map((doc) => (
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
                      <div className="text-xs text-[#222222]">{doc.departmentName || '—'}</div>
                      <div className="text-xs text-[#717171]">
                        {doc.businessCategoryName || 'Nghiệp vụ chung'}
                      </div>
                    </TableCell>
                    <TableCell>
                      <ClassificationBadge level={doc.classificationCode} showRank />
                    </TableCell>
                    <TableCell>
                      {doc.allowDownload ? (
                        <span className="flex items-center gap-1.5 text-xs text-[#008A05]">
                          <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                          <span>Cho phép tải kèm Watermark</span>
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-xs text-[#E07912]">
                          <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                          <span>Chỉ xem trực tuyến</span>
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] font-bold">
                      v{doc.versionCount ?? 1}.0
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          doc.status === 'ACTIVE'
                            ? 'success'
                            : doc.status === 'DRAFT'
                              ? 'secondary'
                              : 'destructive'
                        }
                      >
                        {doc.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1 flex-wrap">
                        {doc.status === 'DRAFT' && (
                          <InteractiveHoverButton
                            variant="primary"
                            size="sm"
                            text="Kích hoạt"
                            icon={<CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onActivate(doc)}
                          />
                        )}
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Xem"
                          icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onOpenPreview(doc)}
                          disabled={isLoadingPreview || doc.status !== 'ACTIVE'}
                        />
                        <InteractiveHoverButton
                          variant={doc.allowDownload ? 'secondary' : 'ghost'}
                          size="sm"
                          text="Tải"
                          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onDownload(doc)}
                          disabled={
                            !doc.allowDownload ||
                            downloadingDocId === doc.id ||
                            doc.status !== 'ACTIVE'
                          }
                          isLoading={downloadingDocId === doc.id}
                        />
                        {doc.status === 'ACTIVE' && (
                          <>
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Bản mới"
                              icon={<Layers size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => onOpenNewVersion(doc)}
                            />
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Đổi mức mật"
                              icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => onOpenReclassify(doc)}
                            />
                            <InteractiveHoverButton
                              variant="ghost"
                              size="sm"
                              text="Lưu trữ"
                              icon={<Archive size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => onOpenArchive(doc)}
                            />
                          </>
                        )}
                        <InteractiveHoverButton
                          variant="ghost"
                          size="sm"
                          text="Lịch sử"
                          icon={<History size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onOpenVersionHistory(doc)}
                        />
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
