'use client';

import { Search, Eye, Send } from 'lucide-react';
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
import type { DiscoverableDoc, MyGrantedDoc } from '../types';

interface CatalogTabProps {
  documents: DiscoverableDoc[];
  myDocs: MyGrantedDoc[];
  searchQuery: string;
  onSearchChange: (value: string) => void;
  selectedClassification: string;
  onClassificationChange: (value: string) => void;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onOpenRequestModal: (doc: DiscoverableDoc) => void;
}

export function CatalogTab({
  documents,
  myDocs,
  searchQuery,
  onSearchChange,
  selectedClassification,
  onClassificationChange,
  onOpenPreview,
  onOpenRequestModal,
}: CatalogTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Danh mục tài liệu tổ chức (Discover Search)
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Tìm kiếm toàn văn hỗ trợ tiếng Việt có dấu. Zero-IDOR: chỉ hiển thị metadata được phép
            phát hiện
          </CardDescription>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
          <select
            aria-label="Lọc theo mức độ mật"
            value={selectedClassification}
            onChange={(e) => onClassificationChange(e.target.value)}
            className="h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            <option value="ALL">Tất cả mức mật</option>
            <option value="UNCLASSIFIED">Không mật</option>
            {/* CONFLICT-RESOLVED: Đổi mã lọc mức Nội bộ từ RESTRICTED sang INTERNAL khớp chuẩn classificationLevelCode từ máy chủ */}
            <option value="INTERNAL">Nội bộ</option>
            <option value="CONFIDENTIAL">Mật</option>
            <option value="SECRET">Tối mật</option>
            <option value="TOP_SECRET">Tuyệt mật</option>
          </select>

          <div className="relative w-full sm:w-64">
            <Search
              size={16}
              strokeWidth={1.75}
              className="pointer-events-none absolute left-3.5 top-3 text-[#717171]"
              aria-hidden="true"
            />
            <Input
              type="text"
              aria-label="Tìm kiếm danh mục tài liệu"
              placeholder="Tìm kiếm tài liệu..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="pl-10 h-10 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
                <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                <TableHead className="text-xs text-[#717171]">Đơn vị chủ quản</TableHead>
                <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Hành động</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {documents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                    Không tìm thấy tài liệu phù hợp với điều kiện tìm kiếm
                  </TableCell>
                </TableRow>
              ) : (
                documents.map((doc) => {
                  const grantedDoc = myDocs.find((m) => m.documentId === doc.id);
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
                      <TableCell className="text-xs text-[#222222]">
                        {doc.departmentName || '—'}
                      </TableCell>
                      <TableCell>
                        {doc.allowDownload ? (
                          <span className="text-xs text-[#008A05] font-medium">Cho phép tải</span>
                        ) : (
                          <span className="text-xs text-[#E07912] font-medium">
                            Chỉ xem trực tuyến
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {grantedDoc ? (
                          <InteractiveHoverButton
                            size="sm"
                            variant="primary"
                            text="Xem tài liệu"
                            icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenPreview(grantedDoc)}
                          />
                        ) : (
                          <InteractiveHoverButton
                            size="sm"
                            variant="secondary"
                            text="Yêu cầu quyền"
                            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenRequestModal(doc)}
                          />
                        )}
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
