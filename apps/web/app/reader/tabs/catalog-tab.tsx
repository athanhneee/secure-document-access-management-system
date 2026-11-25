'use client';

import {
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Eye,
  Loader2,
  Search,
  Send,
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
import { resolveGrantExpiryUrgency } from '../helpers';
import type { DiscoverableDoc, MyGrantedDoc, MyRequestItem } from '../types';

interface CatalogTabProps {
  documents: DiscoverableDoc[];
  myDocs: MyGrantedDoc[];
  myRequests?: MyRequestItem[] | undefined;
  isLoading?: boolean | undefined;
  page?: number | undefined;
  hasMore?: boolean | undefined;
  onPageChange?: ((page: number) => void) | undefined;
  userClearanceRank?: number | undefined;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  selectedClassification: string;
  onClassificationChange: (value: string) => void;
  canViewDocument?: boolean;
  canDownloadDocument?: boolean;
  canRequestAccess?: boolean;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onOpenRequestModal: (doc: DiscoverableDoc, initialAction?: 'VIEW' | 'DOWNLOAD') => void;
}

/**
 * Thuật toán: Danh Mục Tra Cứu Đa Nền Tảng Lọc Theo Bậc Bell-LaPadula, Nâng Quyền & Phân Trang (`CatalogTab`)
 * Mục đích:
 *   - Loại bỏ tùy chọn rác `UNCLASSIFIED`, chỉ hiển thị các mức mật nằm trong thẩm quyền của người xem (`rank <= userClearanceRank`, `V-16`, `V-23`).
 *   - Đánh dấu trạng thái đang chờ duyệt (`PENDING`) tránh gửi trùng lỗi `409` (`V-34`), cho phép xin nâng quyền `DOWNLOAD` hoặc gia hạn khi sắp hết hạn (`V-33`).
 *   - Cung cấp bố cục thẻ di động (`md:hidden`) tối ưu màn hình `375px` song song bảng máy tính và phân trang (`V-22`, `V-37`, `V-41`, `V-58`).
 */
export function CatalogTab({
  documents,
  myDocs,
  myRequests = [],
  isLoading = false,
  page = 1,
  hasMore = false,
  onPageChange,
  userClearanceRank,
  searchQuery,
  onSearchChange,
  selectedClassification,
  onClassificationChange,
  canViewDocument = true,
  canDownloadDocument = true,
  canRequestAccess = true,
  onOpenPreview,
  onOpenRequestModal,
}: CatalogTabProps) {
  const showActionsColumn = canViewDocument || canRequestAccess;
  const maxRank =
    typeof userClearanceRank === 'number' && userClearanceRank > 0 ? userClearanceRank : 4;

  function renderDocActions(doc: DiscoverableDoc) {
    const grantedDoc = myDocs.find((m) => m.documentId === doc.id);
    const hasPendingRequest = myRequests.some(
      (r) =>
        r.status === 'PENDING' &&
        ((r.documentId && r.documentId === doc.id) ||
          (!r.documentId && r.documentTitle === doc.title)),
    );

    if (grantedDoc) {
      const canRequestUpgradeDownload =
        canRequestAccess &&
        !hasPendingRequest &&
        doc.allowDownload &&
        canDownloadDocument &&
        !grantedDoc.permissions.includes('DOWNLOAD');
      const isExpiringSoon = resolveGrantExpiryUrgency(grantedDoc.validUntil) !== 'success';
      const canRequestRenew = canRequestAccess && !hasPendingRequest && isExpiringSoon;

      return (
        <div className="inline-flex flex-wrap items-center justify-end gap-1.5">
          {canViewDocument && (
            <InteractiveHoverButton
              size="sm"
              variant="primary"
              text="Xem tài liệu"
              icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => onOpenPreview(grantedDoc)}
            />
          )}
          {canRequestUpgradeDownload ? (
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Xin quyền tải"
              icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => onOpenRequestModal(doc, 'DOWNLOAD')}
            />
          ) : canRequestRenew ? (
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Xin gia hạn"
              icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => onOpenRequestModal(doc, 'VIEW')}
            />
          ) : hasPendingRequest ? (
            <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-semibold text-[#E07912]">
              <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>Đang chờ duyệt</span>
            </span>
          ) : null}
        </div>
      );
    }

    if (hasPendingRequest) {
      return (
        <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-semibold text-[#E07912]">
          <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>Đang chờ duyệt</span>
        </span>
      );
    }

    if (canRequestAccess) {
      return (
        <InteractiveHoverButton
          size="sm"
          variant="secondary"
          text="Yêu cầu truy cập"
          icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={() => onOpenRequestModal(doc, 'VIEW')}
        />
      );
    }

    return null;
  }

  return (
    <Card>
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Danh mục tài liệu ({documents.length}
          {hasMore ? '+' : ''})
        </CardTitle>
        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto shrink-0">
          <select
            id="reader-catalog-classification"
            name="reader-catalog-classification"
            aria-label="Lọc theo mức độ mật"
            value={selectedClassification}
            onChange={(e) => onClassificationChange(e.target.value)}
            className="min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            <option value="ALL">Tất cả mức độ mật</option>
            {/* CONFLICT-RESOLVED: Giữ đúng 4 cấp độ mật thực tế của CSDL (bỏ UNCLASSIFIED rác) và lọc theo trần Bell-LaPadula của người xem (V-16, V-23). */}
            <option value="INTERNAL">Nội bộ</option>
            {maxRank >= 2 && <option value="CONFIDENTIAL">Mật</option>}
            {maxRank >= 3 && <option value="SECRET">Tối mật</option>}
            {maxRank >= 4 && <option value="TOP_SECRET">Tuyệt mật</option>}
          </select>

          <div className="relative w-full sm:w-64">
            <Search
              size={16}
              strokeWidth={1.75}
              className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
              aria-hidden="true"
            />
            <Input
              id="reader-catalog-search"
              name="reader-catalog-search"
              type="text"
              aria-label="Tìm kiếm danh mục tài liệu"
              placeholder="Tìm tên, mã tài liệu hoặc đơn vị…"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="pl-10 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
            />
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {isLoading && documents.length === 0 ? (
          <div className="py-10 flex flex-col items-center justify-center gap-2 text-xs text-[#717171]">
            <Loader2
              size={20}
              strokeWidth={2}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <span>Đang tải danh mục tài liệu…</span>
          </div>
        ) : documents.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            {searchQuery.trim() || selectedClassification !== 'ALL'
              ? 'Không tìm thấy tài liệu phù hợp với điều kiện lọc.'
              : 'Hiện chưa có tài liệu nào trong danh mục thuộc thẩm quyền của bạn.'}
          </div>
        ) : (
          <>
            {/* Bố cục thẻ di động tối ưu 375px (V-58) */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {documents.map((doc) => (
                <article key={doc.id} className="p-3.5 space-y-2.5 text-xs bg-[#ffffff]">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="font-semibold text-[#222222] break-words">{doc.title}</h3>
                      <div className="text-xs font-bold text-[#717171]">
                        {doc.documentCode || 'Chưa cấp mã'}
                        {doc.businessCategoryName ? ` · ${doc.businessCategoryName}` : ''}
                      </div>
                    </div>
                    <ClassificationBadge level={doc.classificationCode} size="sm" />
                  </div>
                  {doc.description && (
                    <p className="text-xs text-[#717171] line-clamp-2 leading-relaxed">
                      {doc.description}
                    </p>
                  )}
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
                    <span>Đơn vị: {doc.departmentName || '—'}</span>
                    {doc.allowDownload ? (
                      <span className="text-[#008A05] font-medium">Cho phép tải</span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-[#222222] font-medium">
                        <span className="dot dot-warning" aria-hidden="true" />
                        <span>Chỉ xem trực tuyến</span>
                      </span>
                    )}
                  </div>
                  {showActionsColumn && (
                    <div className="pt-1 flex flex-wrap gap-2">{renderDocActions(doc)}</div>
                  )}
                </article>
              ))}
            </div>

            {/* Bảng dữ liệu máy tính */}
            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
                    <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                    <TableHead className="text-xs text-[#717171]">Đơn vị chủ quản</TableHead>
                    <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                    {showActionsColumn && (
                      <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                    )}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {documents.map((doc) => (
                    <TableRow
                      key={doc.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell>
                        <div className="font-semibold text-xs text-[#222222]">{doc.title}</div>
                        <div className="text-xs font-bold text-[#717171]">
                          {doc.documentCode || 'Chưa cấp mã'}
                          {doc.businessCategoryName ? ` · ${doc.businessCategoryName}` : ''}
                        </div>
                        {doc.description && (
                          <div className="text-xs text-[#717171] line-clamp-1 mt-0.5 max-w-md">
                            {doc.description}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <ClassificationBadge level={doc.classificationCode} />
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        {doc.departmentName || '—'}
                      </TableCell>
                      <TableCell>
                        {doc.allowDownload ? (
                          <span className="text-xs text-[#008A05] font-medium">Cho phép tải</span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-xs text-[#222222] font-medium">
                            <span className="dot dot-warning" aria-hidden="true" />
                            <span>Chỉ xem trực tuyến</span>
                          </span>
                        )}
                      </TableCell>
                      {showActionsColumn && (
                        <TableCell className="text-right">{renderDocActions(doc)}</TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {onPageChange && (page > 1 || hasMore) && (
          <div className="flex items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs">
            <span className="text-[#717171] font-medium">Trang {page}</span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page <= 1 || isLoading}
                onClick={() => onPageChange(Math.max(1, page - 1))}
              />
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={!hasMore || isLoading}
                onClick={() => onPageChange(page + 1)}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
