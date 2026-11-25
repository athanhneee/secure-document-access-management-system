'use client';

import { ChevronLeft, ChevronRight, Download, Eye, Loader2, Send } from 'lucide-react';
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
import { formatSafeDateVi } from '@/lib/ui-labels';
import { formatReaderGrantPermissionSummary, resolveGrantExpiryUrgency } from '../helpers';
import type { MyGrantedDoc, MyRequestItem } from '../types';

interface GrantedDocumentsTabProps {
  myDocs: MyGrantedDoc[];
  myRequests?: MyRequestItem[] | undefined;
  isLoading?: boolean | undefined;
  page?: number | undefined;
  hasMore?: boolean | undefined;
  onPageChange?: ((page: number) => void) | undefined;
  downloadingDocIds?: ReadonlySet<string> | undefined;
  downloadingDocId?: string | null | undefined;
  canViewDocument?: boolean;
  canDownloadDocument?: boolean;
  canRequestAccess?: boolean;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onDownload: (doc: MyGrantedDoc) => void;
  onRequestUpgrade?: ((doc: MyGrantedDoc, action: 'VIEW' | 'DOWNLOAD') => void) | undefined;
}

/**
 * Thuật toán: Danh Sách Tài Liệu Được Cấp Quyền Hợp Nhất Nhãn & Tối Ưu Di Động `375px` (`GrantedDocumentsTab`)
 * Mục đích:
 *   - Hợp nhất nhãn quyền thành duy nhất 1 badge (`Xem & Tải về` hoặc `Chỉ xem`, `V-27`), phân biệt rõ nguồn cấp trực tiếp vs theo vai trò (`V-43`) và hiển thị ngày giờ hết hạn `HH:mm` kèm chấm màu động (`V-31`, `V-43`).
 *   - Hỗ trợ tải song song không ghi đè trạng thái (`downloadingDocIds`, `V-42`), nút xin nâng quyền/gia hạn (`V-33`), trạng thái tải `isLoading` (`V-41`) và thẻ di động `md:hidden` (`V-58`).
 */
export function GrantedDocumentsTab({
  myDocs,
  myRequests = [],
  isLoading = false,
  page = 1,
  hasMore = false,
  onPageChange,
  downloadingDocIds,
  downloadingDocId,
  canViewDocument = true,
  canDownloadDocument = true,
  canRequestAccess = false,
  onOpenPreview,
  onDownload,
  onRequestUpgrade,
}: GrantedDocumentsTabProps) {
  function isDocDownloading(documentId: string): boolean {
    if (downloadingDocIds) return downloadingDocIds.has(documentId);
    return downloadingDocId === documentId;
  }

  function renderGrantActions(
    doc: MyGrantedDoc,
    canDownload: boolean,
    expiryUrgency: 'danger' | 'warning' | 'success',
  ) {
    const isDownloading = isDocDownloading(doc.documentId);
    const hasPendingRequest = myRequests.some(
      (r) => r.status === 'PENDING' && r.documentId === doc.documentId,
    );
    const showUpgradeDownload =
      Boolean(onRequestUpgrade) &&
      canRequestAccess &&
      !hasPendingRequest &&
      !canDownload &&
      doc.allowDownload &&
      canDownloadDocument;
    const showRenew =
      Boolean(onRequestUpgrade) &&
      canRequestAccess &&
      !hasPendingRequest &&
      !showUpgradeDownload &&
      expiryUrgency !== 'success';

    return (
      <div className="inline-flex flex-wrap items-center justify-end gap-1.5">
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

        {showUpgradeDownload && onRequestUpgrade && (
          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Xin quyền tải"
            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => onRequestUpgrade(doc, 'DOWNLOAD')}
          />
        )}

        {showRenew && onRequestUpgrade && (
          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Xin gia hạn"
            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => onRequestUpgrade(doc, canDownload ? 'DOWNLOAD' : 'VIEW')}
          />
        )}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Tài liệu được cấp quyền ({myDocs.length}
          {hasMore ? '+' : ''})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading && myDocs.length === 0 ? (
          <div className="py-10 flex flex-col items-center justify-center gap-2 text-xs text-[#717171]">
            <Loader2
              size={20}
              strokeWidth={2}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <span>Đang tải danh sách tài liệu được cấp quyền…</span>
          </div>
        ) : myDocs.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            Bạn chưa có tài liệu nào được cấp quyền truy cập còn hiệu lực.
          </div>
        ) : (
          <>
            {/* Bố cục thẻ di động tối ưu 375px (V-58) */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {myDocs.map((doc) => {
                const permSummary = formatReaderGrantPermissionSummary(
                  doc.permissions,
                  doc.allowDownload,
                  canDownloadDocument,
                );
                const urgency = resolveGrantExpiryUrgency(doc.validUntil);
                const dotClass =
                  urgency === 'danger'
                    ? 'dot-danger'
                    : urgency === 'warning'
                      ? 'dot-warning'
                      : 'dot-success';
                return (
                  <article key={doc.id} className="p-3.5 space-y-2.5 text-xs bg-[#ffffff]">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="font-semibold text-[#222222] break-words">{doc.title}</h3>
                        <div className="text-xs font-bold text-[#717171]">
                          {doc.documentCode || 'Chưa cấp mã'}
                        </div>
                      </div>
                      <ClassificationBadge level={doc.classificationCode} size="sm" />
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Badge variant={permSummary.canDownload ? 'info' : 'secondary'}>
                        {permSummary.label}
                      </Badge>
                      <span className="text-xs text-[#717171]">
                        {doc.principalType === 'ROLE'
                          ? `Theo vai trò${doc.roleName ? `: ${doc.roleName}` : ''}`
                          : 'Cấp trực tiếp'}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
                      <span>Từ: {formatSafeDateVi(doc.validFrom, { includeTime: true })}</span>
                      <span className="inline-flex items-center gap-1.5 font-semibold text-[#222222]">
                        <span className={`dot ${dotClass}`} aria-hidden="true" />
                        <span>Đến: {formatSafeDateVi(doc.validUntil, { includeTime: true })}</span>
                      </span>
                    </div>
                    <div className="pt-1 flex flex-wrap gap-2">
                      {renderGrantActions(doc, permSummary.canDownload, urgency)}
                    </div>
                  </article>
                );
              })}
            </div>

            {/* Bảng dữ liệu máy tính */}
            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Tên tài liệu / Mã số</TableHead>
                    <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                    <TableHead className="text-xs text-[#717171]">Quyền &amp; nguồn cấp</TableHead>
                    <TableHead className="text-xs text-[#717171]">Hiệu lực đến</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {myDocs.map((doc) => {
                    const permSummary = formatReaderGrantPermissionSummary(
                      doc.permissions,
                      doc.allowDownload,
                      canDownloadDocument,
                    );
                    const urgency = resolveGrantExpiryUrgency(doc.validUntil);
                    const dotClass =
                      urgency === 'danger'
                        ? 'dot-danger'
                        : urgency === 'warning'
                          ? 'dot-warning'
                          : 'dot-success';

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
                          <div className="flex flex-col gap-0.5">
                            <Badge variant={permSummary.canDownload ? 'info' : 'secondary'}>
                              {permSummary.label}
                            </Badge>
                            <span className="text-xs text-[#717171]">
                              {doc.principalType === 'ROLE'
                                ? `Theo vai trò${doc.roleName ? `: ${doc.roleName}` : ''}`
                                : 'Cấp trực tiếp'}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs text-[#222222]">
                          <div className="flex flex-col gap-0.5">
                            <span className="inline-flex items-center gap-1.5 font-bold">
                              <span className={`dot ${dotClass}`} aria-hidden="true" />
                              <span>{formatSafeDateVi(doc.validUntil, { includeTime: true })}</span>
                            </span>
                            {doc.validFrom && (
                              <span className="text-xs text-[#717171]">
                                Từ: {formatSafeDateVi(doc.validFrom, { includeTime: true })}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          {renderGrantActions(doc, permSummary.canDownload, urgency)}
                        </TableCell>
                      </TableRow>
                    );
                  })}
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
