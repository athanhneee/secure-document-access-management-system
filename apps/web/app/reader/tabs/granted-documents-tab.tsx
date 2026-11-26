'use client';

import Link from 'next/link';
import { ChevronLeft, ChevronRight, Download, Eye, Loader2, Send, ShieldCheck } from 'lucide-react';
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
import {
  resolveDocumentAccessPrecheck,
  type SessionSecurityPosture,
} from '@/lib/use-session-posture';
import {
  formatReaderGrantPermissionSummary,
  rankFromCode,
  resolveGrantExpiryUrgency,
} from '../helpers';
import type { MyGrantedDoc, MyRequestItem } from '../types';

interface GrantedDocumentsTabProps {
  myDocs: MyGrantedDoc[];
  myRequests?: MyRequestItem[] | undefined;
  pendingRequestDocIds?: ReadonlySet<string> | undefined;
  isLoading?: boolean | undefined;
  page?: number | undefined;
  hasMore?: boolean | undefined;
  onPageChange?: ((page: number) => void) | undefined;
  openingDocId?: string | null | undefined;
  downloadingDocIds?: ReadonlySet<string> | undefined;
  downloadingDocId?: string | null | undefined;
  sessionPosture?: SessionSecurityPosture | null | undefined;
  mfaActionHref?: string | undefined;
  canViewDocument?: boolean;
  canDownloadDocument?: boolean;
  canRequestAccess?: boolean;
  onOpenPreview: (doc: MyGrantedDoc) => void;
  onDownload: (doc: MyGrantedDoc) => void;
  onRequestUpgrade?:
    | ((
        doc: MyGrantedDoc,
        action: 'VIEW' | 'DOWNLOAD',
        intent?: 'UPGRADE_DOWNLOAD' | 'RENEW',
      ) => void)
    | undefined;
}

/**
 * Thuật toán: Định Dạng Nhãn Nguồn Cấp Quyền Đã Hợp Nhất (`formatGrantSourceLabel`, BUG-119)
 */
function formatGrantSourceLabel(doc: MyGrantedDoc): string {
  if (doc.hasDirectAndRoleGrant) {
    return doc.roleName
      ? `Cấp trực tiếp & Theo vai trò: ${doc.roleName}`
      : 'Cấp trực tiếp & Theo vai trò';
  }
  if (doc.principalType === 'ROLE') {
    return `Theo vai trò${doc.roleName ? `: ${doc.roleName}` : ''}`;
  }
  return 'Cấp trực tiếp';
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
  pendingRequestDocIds,
  isLoading = false,
  page = 1,
  hasMore = false,
  onPageChange,
  openingDocId = null,
  downloadingDocIds,
  downloadingDocId,
  sessionPosture = null,
  mfaActionHref = '/mfa?redirect=%2Freader',
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
    mobileLayout = false,
  ) {
    const isDownloading = isDocDownloading(doc.documentId);
    const hasPendingRequest = pendingRequestDocIds
      ? pendingRequestDocIds.has(doc.documentId)
      : myRequests.some((r) => r.status === 'PENDING' && r.documentId === doc.documentId);
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
    const precheck = resolveDocumentAccessPrecheck(
      sessionPosture,
      rankFromCode(doc.classificationCode),
    );
    const isOpening = openingDocId === doc.documentId;

    const buttonCount =
      Number(canViewDocument) +
      Number(canDownload) +
      Number(showUpgradeDownload) +
      Number(showRenew);

    return (
      <div
        className={
          mobileLayout
            ? buttonCount >= 2
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
              onClick={() => onOpenPreview(doc)}
              className={mobileLayout ? 'w-full' : undefined}
            />
          ))}

        {canDownload && (
          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Tải bản sao"
            icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
            disabled={isDownloading || precheck.blocked}
            isLoading={isDownloading}
            onClick={() => onDownload(doc)}
            title={precheck.reason ?? 'Tải bản sao có watermark bảo mật'}
            className={mobileLayout ? 'w-full' : undefined}
          />
        )}

        {showUpgradeDownload && onRequestUpgrade && (
          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Xin quyền tải"
            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => onRequestUpgrade(doc, 'DOWNLOAD', 'UPGRADE_DOWNLOAD')}
            className={mobileLayout ? 'w-full' : undefined}
          />
        )}

        {showRenew && onRequestUpgrade && (
          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Xin gia hạn"
            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => onRequestUpgrade(doc, canDownload ? 'DOWNLOAD' : 'VIEW', 'RENEW')}
            className={mobileLayout ? 'w-full' : undefined}
          />
        )}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb]">
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
                  <article key={doc.documentId} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                    <div className="flex items-center justify-between gap-2">
                      <ClassificationBadge level={doc.classificationCode} size="sm" />
                      <span className="font-mono text-xs text-[#717171] truncate">
                        {doc.documentCode || 'Chưa cấp mã'}
                      </span>
                    </div>

                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {doc.title}
                    </h3>

                    <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Quyền hạn</span>
                        <Badge variant={permSummary.canDownload ? 'info' : 'secondary'}>
                          {permSummary.label}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Nguồn cấp</span>
                        <span className="font-medium text-[#222222] text-right truncate">
                          {formatGrantSourceLabel(doc)}
                        </span>
                      </div>
                      {doc.validFrom && (
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[#717171] shrink-0">Hiệu lực từ</span>
                          <span className="text-[#717171] tabular-nums">
                            {formatSafeDateVi(doc.validFrom, { includeTime: true })}
                          </span>
                        </div>
                      )}
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Hiệu lực đến</span>
                        <span className="inline-flex items-center gap-1.5 font-semibold text-[#222222] tabular-nums whitespace-nowrap">
                          <span className={`dot ${dotClass}`} aria-hidden="true" />
                          <span>{formatSafeDateVi(doc.validUntil, { includeTime: true })}</span>
                        </span>
                      </div>
                    </div>

                    <div className="pt-0.5">
                      {renderGrantActions(doc, permSummary.canDownload, urgency, true)}
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
                        key={doc.documentId}
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
                              {formatGrantSourceLabel(doc)}
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
