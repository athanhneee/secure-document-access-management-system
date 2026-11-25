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
import type { DocumentItem } from '../types';

interface DocumentsTabProps {
  documents: DocumentItem[];
  searchQuery: string;
  onSearchChange: (value: string) => void;
  isLoadingPreview: boolean;
  downloadingDocId: string | null;
  canManage?: boolean;
  canView?: boolean;
  canDownload?: boolean;
  canCreateVersion?: boolean;
  canClassify?: boolean;
  canArchive?: boolean;
  onActivate: (doc: DocumentItem) => void;
  onOpenPreview: (doc: DocumentItem) => void;
  onDownload: (doc: DocumentItem) => void;
  onOpenNewVersion: (doc: DocumentItem) => void;
  onOpenReclassify: (doc: DocumentItem) => void;
  onOpenArchive: (doc: DocumentItem) => void;
  onOpenVersionHistory: (doc: DocumentItem) => void;
}

/**
 * Thuật toán: Bảng Quản Lý Kho Tài Liệu Ẩn Thao Tác Không Đủ Quyền / Trạng Thái (`DocumentsTab`)
 * Mục đích: Chỉ hiển thị các nút thao tác hợp lệ theo cả quyền RBAC của người dùng và trạng thái vòng đời (`DRAFT` / `ACTIVE`) cùng chính sách `allowDownload` của tài liệu.
 */
export function DocumentsTab({
  documents,
  searchQuery,
  onSearchChange,
  isLoadingPreview,
  downloadingDocId,
  canManage = true,
  canView = true,
  canDownload = true,
  canCreateVersion = true,
  canClassify = true,
  canArchive = true,
  onActivate,
  onOpenPreview,
  onDownload,
  onOpenNewVersion,
  onOpenReclassify,
  onOpenArchive,
  onOpenVersionHistory,
}: DocumentsTabProps) {
  return (
    <Card>
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Kho tài liệu đang quản lý ({documents.length})
        </CardTitle>
        <div className="relative w-full sm:w-64 shrink-0">
          <Search
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            id="owner-documents-search"
            name="owner-documents-search"
            type="text"
            aria-label="Tìm kiếm tài liệu theo tiêu đề hoặc mã số"
            placeholder="Tìm theo tiêu đề, mã số..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-9 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tài liệu</TableHead>
              <TableHead>Đơn vị &amp; Danh mục</TableHead>
              <TableHead>Mức mật &amp; Chính sách</TableHead>
              <TableHead>Trạng thái</TableHead>
              <TableHead className="text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {documents.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                  Chưa có tài liệu nào trong danh mục quản lý
                </TableCell>
              </TableRow>
            ) : (
              documents.map((doc) => (
                <TableRow key={doc.id}>
                  <TableCell>
                    <div className="font-semibold text-xs text-[#222222] max-w-[230px] truncate">
                      {doc.title}
                    </div>
                    <div className="text-xs text-[#717171]">
                      {doc.documentCode || 'DOC-' + doc.id.slice(0, 8)} · v{doc.versionCount ?? 1}.0
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <div className="text-xs text-[#222222]">{doc.departmentName || '—'}</div>
                    <div className="text-xs text-[#717171]">{doc.businessCategoryName || '—'}</div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <div className="flex flex-col items-start gap-0.5">
                      <ClassificationBadge level={doc.classificationCode} showRank />
                      <span
                        className={`text-xs font-medium ${doc.allowDownload ? 'text-[#008A05]' : 'text-[#717171]'}`}
                      >
                        {doc.allowDownload ? 'Cho phép tải' : 'Chỉ xem trực tuyến'}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
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
                  <TableCell className="text-right whitespace-nowrap">
                    <div className="inline-flex items-center justify-end gap-1">
                      {doc.status === 'DRAFT' && canManage && (
                        <InteractiveHoverButton
                          variant="primary"
                          size="sm"
                          text="Kích hoạt"
                          icon={<CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onActivate(doc)}
                        />
                      )}
                      {doc.status === 'ACTIVE' && canView && (
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Xem"
                          icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onOpenPreview(doc)}
                          disabled={isLoadingPreview}
                        />
                      )}
                      {doc.status === 'ACTIVE' && doc.allowDownload && canDownload && (
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Tải"
                          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onDownload(doc)}
                          disabled={downloadingDocId === doc.id}
                          isLoading={downloadingDocId === doc.id}
                        />
                      )}
                      {doc.status === 'ACTIVE' && canCreateVersion && (
                        <button
                          type="button"
                          onClick={() => onOpenNewVersion(doc)}
                          title="Tải lên phiên bản mới"
                          aria-label="Tải lên phiên bản mới"
                          className="inline-flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer"
                        >
                          <Layers size={16} strokeWidth={1.75} aria-hidden="true" />
                        </button>
                      )}
                      {doc.status === 'ACTIVE' && canClassify && (
                        <button
                          type="button"
                          onClick={() => onOpenReclassify(doc)}
                          title="Đổi mức độ mật"
                          aria-label="Đổi mức độ mật"
                          className="inline-flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer"
                        >
                          <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                        </button>
                      )}
                      {doc.status === 'ACTIVE' && canArchive && (
                        <button
                          type="button"
                          onClick={() => onOpenArchive(doc)}
                          title="Lưu trữ tài liệu"
                          aria-label="Lưu trữ tài liệu"
                          className="inline-flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#C13515] transition-colors cursor-pointer"
                        >
                          <Archive size={16} strokeWidth={1.75} aria-hidden="true" />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => onOpenVersionHistory(doc)}
                        title="Lịch sử phiên bản & phân loại"
                        aria-label="Lịch sử phiên bản và phân loại"
                        className="inline-flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer"
                      >
                        <History size={16} strokeWidth={1.75} aria-hidden="true" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
