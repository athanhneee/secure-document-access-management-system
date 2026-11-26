'use client';

import Link from 'next/link';
import {
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Eye,
  Loader2,
  Search,
  Send,
  ShieldCheck,
  X,
} from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import {
  resolveDocumentAccessPrecheck,
  type SessionSecurityPosture,
} from '@/lib/use-session-posture';
import { resolveGrantExpiryUrgency } from '../helpers';
import type { DiscoverableDoc, MyGrantedDoc, MyRequestItem } from '../types';

interface CatalogTabProps {
  documents: DiscoverableDoc[];
  myDocs: MyGrantedDoc[];
  activeGrantsByDocId?: ReadonlyMap<string, MyGrantedDoc> | undefined;
  myRequests?: MyRequestItem[] | undefined;
  pendingRequestDocIds?: ReadonlySet<string> | undefined;
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
  openingDocId?: string | null | undefined;
  sessionPosture?: SessionSecurityPosture | null | undefined;
  mfaActionHref?: string | undefined;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onOpenRequestModal: (
    doc: DiscoverableDoc,
    initialAction?: 'VIEW' | 'DOWNLOAD',
    options?: {
      existingGrantValidUntil?: string | null | undefined;
      intent?: 'NEW' | 'UPGRADE_DOWNLOAD' | 'RENEW' | undefined;
    },
  ) => void;
}

/**
 * Thuật toán: Danh Mục Tra Cứu Đa Nền Tảng Lọc Theo Bậc Bell-LaPadula, Nâng Quyền & Phân Trang (`CatalogTab`)
 * Mục đích:
 *   - Loại bỏ tùy chọn rác `UNCLASSIFIED`, chỉ hiển thị các mức mật nằm trong thẩm quyền của người xem (`rank <= userClearanceRank`, `V-16`, `V-23`).
 *   - Đánh dấu trạng thái đang chờ duyệt (`PENDING`) tránh gửi trùng lỗi `409` (`V-34`), cho phép xin nâng quyền `DOWNLOAD` hoặc gia hạn khi sắp hết hạn (`V-33`).
 *   - Cung cấp bố cục thẻ di động (`md:hidden`) thoáng rõ, phân cấp thị giác mạch lạc trên `375px` song song bảng máy tính và phân trang (`V-22`, `V-37`, `V-41`, `V-58`).
 */
export function CatalogTab({
  documents,
  myDocs,
  activeGrantsByDocId,
  myRequests = [],
  pendingRequestDocIds,
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
  openingDocId = null,
  sessionPosture = null,
  mfaActionHref = '/mfa?redirect=%2Freader',
  onOpenPreview,
  onOpenRequestModal,
}: CatalogTabProps) {
  const showActionsColumn = canViewDocument || canRequestAccess;
  const maxRank =
    typeof userClearanceRank === 'number' &&
    Number.isFinite(userClearanceRank) &&
    userClearanceRank >= 0
      ? userClearanceRank
      : 4;

  function renderDocActions(doc: DiscoverableDoc, mobileLayout = false) {
    const grantedDoc = activeGrantsByDocId
      ? activeGrantsByDocId.get(doc.id)
      : myDocs.find((m) => m.documentId === doc.id);
    const hasPendingRequest = pendingRequestDocIds
      ? pendingRequestDocIds.has(doc.id)
      : myRequests.some(
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
      const hasSecondaryAction = canRequestUpgradeDownload || canRequestRenew;
      const precheck = resolveDocumentAccessPrecheck(sessionPosture, doc.classificationRank);
      const isOpening = openingDocId === grantedDoc.documentId;

      return (
        <div
          className={
            mobileLayout
              ? hasSecondaryAction && canViewDocument
                ? 'grid grid-cols-2 gap-2 w-full'
                : 'flex flex-col gap-2 w-full'
              : 'inline-flex flex-wrap items-center justify-end gap-1.5'
          }
        >
          {canViewDocument &&
            (precheck.blocked && precheck.requiresMfa ? (
              <Link
                href={mfaActionHref}
                title={precheck.reason ?? undefined}
                className={`inline-flex min-h-11 sm:min-h-8 items-center justify-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 py-1.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors ${mobileLayout ? 'w-full' : ''}`}
              >
                <ShieldCheck
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#E07912]"
                  aria-hidden="true"
                />
                <span>Cần xác thực MFA</span>
              </Link>
            ) : (
              <InteractiveHoverButton
                size="sm"
                variant="primary"
                text="Xem tài liệu"
                icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                isLoading={isOpening}
                disabled={Boolean(openingDocId) || precheck.blocked}
                title={precheck.reason ?? undefined}
                onClick={() => onOpenPreview(grantedDoc)}
                className={mobileLayout ? 'w-full' : undefined}
              />
            ))}
          {canRequestUpgradeDownload ? (
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Xin quyền tải"
              icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() =>
                onOpenRequestModal(doc, 'DOWNLOAD', {
                  existingGrantValidUntil: grantedDoc.validUntil,
                  intent: 'UPGRADE_DOWNLOAD',
                })
              }
              className={mobileLayout ? 'w-full' : undefined}
            />
          ) : canRequestRenew ? (
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Xin gia hạn"
              icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() =>
                onOpenRequestModal(
                  doc,
                  grantedDoc.permissions.includes('DOWNLOAD') &&
                    doc.allowDownload &&
                    canDownloadDocument
                    ? 'DOWNLOAD'
                    : 'VIEW',
                  {
                    existingGrantValidUntil: grantedDoc.validUntil,
                    intent: 'RENEW',
                  },
                )
              }
              className={mobileLayout ? 'w-full' : undefined}
            />
          ) : hasPendingRequest ? (
            <span
              className={`staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-semibold text-[#222222] ${mobileLayout ? 'justify-center py-1' : ''}`}
            >
              <Clock size={16} strokeWidth={1.75} className="text-[#E07912]" aria-hidden="true" />
              <span>Đang chờ duyệt</span>
            </span>
          ) : null}
        </div>
      );
    }

    if (hasPendingRequest) {
      return (
        <span
          className={`staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-semibold text-[#222222] ${mobileLayout ? 'w-full justify-center py-1.5' : ''}`}
        >
          <Clock size={16} strokeWidth={1.75} className="text-[#E07912]" aria-hidden="true" />
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
          className={mobileLayout ? 'w-full' : undefined}
        />
      );
    }

    return null;
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
          Danh mục tài liệu ({documents.length}
          {hasMore ? '+' : ''})
        </CardTitle>

        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto shrink-0">
          <div className="relative w-full sm:w-64 sm:order-2">
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
              maxLength={200}
              aria-label="Tìm kiếm danh mục tài liệu"
              placeholder="Tìm tên, mã tài liệu hoặc đơn vị…"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className={`pl-10 ${searchQuery ? 'pr-11 sm:pr-10' : ''} h-11 sm:h-9 rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 shadow-2xs`}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                aria-label="Xóa từ khóa tìm kiếm"
                className="absolute right-0.5 sm:right-1.5 top-1/2 -translate-y-1/2 flex h-11 w-11 sm:h-7 sm:w-7 items-center justify-center rounded-full text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] cursor-pointer"
              >
                <X size={16} strokeWidth={2} aria-hidden="true" />
              </button>
            )}
          </div>

          <Select
            id="reader-catalog-classification"
            name="reader-catalog-classification"
            aria-label="Lọc theo mức độ mật"
            value={selectedClassification}
            onChange={(e) => onClassificationChange(e.target.value)}
            wrapperClassName="w-full sm:w-44 sm:order-1"
          >
            <option value="ALL">Tất cả mức độ mật</option>
            {/* CONFLICT-RESOLVED: Giữ đúng 4 cấp độ mật thực tế của CSDL (bỏ UNCLASSIFIED rác) và lọc theo trần Bell-LaPadula của người xem (V-16, V-23, MED-25). */}
            {maxRank >= 1 && <option value="INTERNAL">Nội bộ</option>}
            {maxRank >= 2 && <option value="CONFIDENTIAL">Mật</option>}
            {maxRank >= 3 && <option value="SECRET">Tối mật</option>}
            {maxRank >= 4 && <option value="TOP_SECRET">Tuyệt mật</option>}
          </Select>
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
                <article key={doc.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                  <div className="flex items-center justify-between gap-2">
                    <ClassificationBadge level={doc.classificationCode} size="sm" />
                    <span className="font-mono text-xs text-[#717171] truncate">
                      {doc.documentCode || 'Chưa cấp mã'}
                    </span>
                  </div>

                  <div className="space-y-0.5 min-w-0">
                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {doc.title}
                    </h3>
                    {doc.businessCategoryName && (
                      <p className="text-xs text-[#717171] leading-snug">
                        {doc.businessCategoryName}
                      </p>
                    )}
                    {doc.description && (
                      <p className="text-xs text-[#717171] line-clamp-2 leading-relaxed pt-0.5">
                        {doc.description}
                      </p>
                    )}
                  </div>

                  <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Đơn vị</span>
                      <span className="font-medium text-[#222222] text-right truncate">
                        {doc.departmentName || '—'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Chính sách</span>
                      {doc.allowDownload ? (
                        <span className="inline-flex items-center gap-1.5 text-[#008A05] font-semibold whitespace-nowrap">
                          <span className="dot dot-success" aria-hidden="true" />
                          <span>Cho phép tải</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[#222222] font-semibold whitespace-nowrap">
                          <span className="dot dot-warning" aria-hidden="true" />
                          <span>Chỉ xem trực tuyến</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {showActionsColumn && <div className="pt-0.5">{renderDocActions(doc, true)}</div>}
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
                          <span className="inline-flex items-center gap-1.5 text-xs text-[#008A05] font-medium whitespace-nowrap">
                            <span className="dot dot-success" aria-hidden="true" />
                            <span>Cho phép tải</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-xs text-[#222222] font-medium whitespace-nowrap">
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
            <span className="text-[#717171] font-medium tabular-nums">Trang {page}</span>
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
