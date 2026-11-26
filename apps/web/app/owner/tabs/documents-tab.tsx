'use client';

import Link from 'next/link';
import {
  Search,
  Download,
  Eye,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Layers,
  ShieldCheck,
  Archive,
  History,
  Pencil,
  ArrowRightLeft,
  X,
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
import { formatDocumentStatusLabel } from '@/lib/ui-labels';
import {
  resolveDocumentAccessPrecheck,
  type SessionSecurityPosture,
} from '@/lib/use-session-posture';
import { rankFromCode } from '@/app/reader/helpers';
import type { DocumentItem } from '../types';

interface DocumentsTabProps {
  documents: DocumentItem[];
  docsPage?: number | undefined;
  docsHasMore?: boolean | undefined;
  isLoadingDocs?: boolean | undefined;
  onLoadDocsPage?: ((page: number) => void) | undefined;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  isLoadingPreview: boolean;
  openingDocId?: string | null | undefined;
  activatingDocIds?: ReadonlySet<string> | undefined;
  downloadingDocIds?: ReadonlySet<string> | undefined;
  downloadingDocId?: string | null | undefined;
  sessionPosture?: SessionSecurityPosture | null | undefined;
  mfaActionHref?: string | undefined;
  canUpload?: boolean;
  canManage?: boolean;
  canView?: boolean;
  canDownload?: boolean;
  canCreateVersion?: boolean;
  canClassify?: boolean;
  canArchive?: boolean;
  onActivate: (doc: DocumentItem) => Promise<void> | void;
  onOpenPreview: (doc: DocumentItem) => void;
  onDownload: (doc: DocumentItem) => void;
  onOpenEditMetadata?: ((doc: DocumentItem) => void) | undefined;
  onOpenTransferOwner?: ((doc: DocumentItem) => void) | undefined;
  onOpenNewVersion: (doc: DocumentItem) => void;
  onOpenReclassify: (doc: DocumentItem) => void;
  onOpenArchive: (doc: DocumentItem) => void;
  onOpenVersionHistory: (doc: DocumentItem) => void;
}

/**
 * Thuật toán: Bảng Quản Lý Kho Tài Liệu Đầy Đủ Thao Tác Cho Cả `DRAFT` Lẫn `ACTIVE` & Phân Trang `375px` (`DocumentsTab`, BUG-101, BUG-102)
 * Mục đích:
 *   - Cho phép tải phiên bản mới, phân loại lại và lưu trữ trên cả tài liệu `DRAFT` lẫn `ACTIVE` để bản nháp không bao giờ bị kẹt cứng.
 *   - Trả trực tiếp `Promise` kích hoạt cho `InteractiveHoverButton` kèm khóa theo từng `doc.id` (`activatingDocIds`) và hỗ trợ phân trang > 50 tài liệu.
 */
export function DocumentsTab({
  documents,
  docsPage = 1,
  docsHasMore = false,
  isLoadingDocs = false,
  onLoadDocsPage,
  searchQuery,
  onSearchChange,
  isLoadingPreview,
  openingDocId = null,
  activatingDocIds,
  downloadingDocIds,
  downloadingDocId = null,
  sessionPosture = null,
  mfaActionHref = '/mfa?redirect=%2Fowner',
  canUpload = true,
  canManage = true,
  canView = true,
  canDownload = true,
  canCreateVersion = true,
  canClassify = true,
  canArchive = true,
  onActivate,
  onOpenPreview,
  onDownload,
  onOpenEditMetadata,
  onOpenTransferOwner,
  onOpenNewVersion,
  onOpenReclassify,
  onOpenArchive,
  onOpenVersionHistory,
}: DocumentsTabProps) {
  function isDocDownloading(docId: string): boolean {
    if (downloadingDocIds) return downloadingDocIds.has(docId);
    return downloadingDocId === docId;
  }

  const canUploadNewVersion = canUpload && canCreateVersion;
  function getStatusVariant(status: DocumentItem['status']) {
    if (status === 'ACTIVE') return 'success' as const;
    if (status === 'DRAFT') return 'secondary' as const;
    return 'destructive' as const;
  }

  function renderLifecycleIconButtons(doc: DocumentItem, isMobile: boolean) {
    const canMutateLifecycle = doc.status === 'ACTIVE' || doc.status === 'DRAFT';
    const sizeCls = isMobile ? 'h-11 w-11' : 'h-8 w-8';
    return (
      <>
        {canMutateLifecycle && canClassify && onOpenEditMetadata && (
          <button
            type="button"
            onClick={() => onOpenEditMetadata(doc)}
            title="Chỉnh sửa thông tin tài liệu"
            aria-label="Chỉnh sửa thông tin tài liệu"
            className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer`}
          >
            <Pencil size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        )}
        {canMutateLifecycle && canManage && onOpenTransferOwner && (
          <button
            type="button"
            onClick={() => onOpenTransferOwner(doc)}
            title="Chuyển chủ sở hữu tài liệu"
            aria-label="Chuyển chủ sở hữu tài liệu"
            className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer`}
          >
            <ArrowRightLeft size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        )}
        {canMutateLifecycle && canUploadNewVersion && (
          <button
            type="button"
            onClick={() => onOpenNewVersion(doc)}
            title="Tải lên phiên bản mới"
            aria-label="Tải lên phiên bản mới"
            className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer`}
          >
            <Layers size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        )}
        {canMutateLifecycle && canClassify && (
          <button
            type="button"
            onClick={() => onOpenReclassify(doc)}
            title="Phân loại lại mức độ mật"
            aria-label="Phân loại lại mức độ mật"
            className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer`}
          >
            <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        )}
        {canMutateLifecycle && canArchive && (
          <button
            type="button"
            onClick={() => onOpenArchive(doc)}
            title="Lưu trữ tài liệu"
            aria-label="Lưu trữ tài liệu"
            className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#C13515] transition-colors cursor-pointer`}
          >
            <Archive size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        )}
        <button
          type="button"
          onClick={() => onOpenVersionHistory(doc)}
          title="Lịch sử phiên bản & phân loại"
          aria-label="Lịch sử phiên bản và phân loại"
          className={`inline-flex ${sizeCls} items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer`}
        >
          <History size={16} strokeWidth={1.75} aria-hidden="true" />
        </button>
      </>
    );
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
          Kho tài liệu đang quản lý ({documents.length}
          {docsHasMore ? '+' : ''})
        </CardTitle>
        <div className="relative w-full sm:w-64 shrink-0">
          <Search
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            id="owner-documents-search"
            name="owner-documents-search"
            type="text"
            maxLength={200}
            aria-label="Tìm kiếm tài liệu theo tiêu đề hoặc mã số"
            placeholder="Tìm theo tiêu đề hoặc mã tài liệu…"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className={`pl-10 ${searchQuery ? 'pr-11 sm:pr-10' : ''} h-11 sm:h-9 rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#222222]`}
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
      </CardHeader>
      <CardContent className="p-0">
        {documents.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            {searchQuery.trim()
              ? 'Không tìm thấy tài liệu phù hợp với từ khóa tìm kiếm.'
              : 'Chưa có tài liệu nào trong danh mục quản lý.'}
          </div>
        ) : (
          <>
            {/* Bố cục thẻ di động tối ưu 375px */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {documents.map((doc) => {
                const precheck = resolveDocumentAccessPrecheck(
                  sessionPosture,
                  doc.classificationRank ?? rankFromCode(doc.classificationCode),
                );
                const isOpening = openingDocId === doc.id;
                const isActivating = Boolean(activatingDocIds?.has(doc.id));
                return (
                  <article key={doc.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                    <div className="flex items-center justify-between gap-2">
                      <ClassificationBadge level={doc.classificationCode} showRank size="sm" />
                      <Badge variant={getStatusVariant(doc.status)}>
                        {formatDocumentStatusLabel(doc.status)}
                      </Badge>
                    </div>
                    <div className="space-y-0.5 min-w-0">
                      <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                        {doc.title}
                      </h3>
                      <p className="font-mono text-xs text-[#717171] truncate">
                        {doc.documentCode || 'Chưa cấp mã'} · Phiên bản v
                        {doc.currentVersionNo ?? doc.versionCount ?? 1}
                      </p>
                    </div>
                    <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Đơn vị</span>
                        <span className="font-medium text-[#222222] text-right truncate">
                          {doc.departmentName || '—'}
                        </span>
                      </div>
                      {doc.businessCategoryName && (
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[#717171] shrink-0">Danh mục</span>
                          <span className="text-[#222222] text-right truncate">
                            {doc.businessCategoryName}
                          </span>
                        </div>
                      )}
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

                    <div className="flex flex-wrap items-center gap-2 pt-0.5">
                      {doc.status === 'DRAFT' && canClassify && (
                        <InteractiveHoverButton
                          variant="primary"
                          size="sm"
                          text="Kích hoạt"
                          icon={<CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                          isLoading={isActivating}
                          disabled={isActivating}
                          onClick={() => onActivate(doc)}
                          className="flex-1 min-w-[120px]"
                        />
                      )}
                      {doc.status === 'ACTIVE' &&
                        canView &&
                        (precheck.blocked && precheck.requiresMfa ? (
                          <Link
                            href={mfaActionHref}
                            title={precheck.reason ?? undefined}
                            className="inline-flex flex-1 min-w-[110px] min-h-11 items-center justify-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 py-1.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
                          >
                            <ShieldCheck
                              size={16}
                              strokeWidth={1.75}
                              className="text-[#E07912]"
                              aria-hidden="true"
                            />
                            <span>Cần MFA</span>
                          </Link>
                        ) : (
                          <InteractiveHoverButton
                            variant="primary"
                            size="sm"
                            text="Xem"
                            icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenPreview(doc)}
                            isLoading={isOpening}
                            disabled={isLoadingPreview || Boolean(openingDocId) || precheck.blocked}
                            title={precheck.reason ?? undefined}
                            className="flex-1 min-w-[100px]"
                          />
                        ))}
                      {doc.status === 'ACTIVE' && doc.allowDownload && canDownload && (
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Tải"
                          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onDownload(doc)}
                          disabled={isDocDownloading(doc.id) || precheck.blocked}
                          isLoading={isDocDownloading(doc.id)}
                          title={precheck.reason ?? undefined}
                          className="flex-1 min-w-[100px]"
                        />
                      )}
                      <div className="flex flex-wrap items-center gap-1.5 ml-auto">
                        {renderLifecycleIconButtons(doc, true)}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>

            {/* Bảng dữ liệu máy tính */}
            <div className="hidden md:block">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tài liệu</TableHead>
                    <TableHead>Phòng ban &amp; Danh mục</TableHead>
                    <TableHead>Mức độ mật &amp; Chính sách</TableHead>
                    <TableHead>Trạng thái</TableHead>
                    <TableHead className="text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {documents.map((doc) => {
                    const precheck = resolveDocumentAccessPrecheck(
                      sessionPosture,
                      doc.classificationRank ?? rankFromCode(doc.classificationCode),
                    );
                    const isOpening = openingDocId === doc.id;
                    const isActivating = Boolean(activatingDocIds?.has(doc.id));
                    return (
                      <TableRow key={doc.id}>
                        <TableCell>
                          <div className="font-semibold text-xs text-[#222222] max-w-[230px] truncate">
                            {doc.title}
                          </div>
                          <div className="text-xs text-[#717171]">
                            {doc.documentCode || 'Chưa cấp mã'} · Phiên bản v
                            {doc.currentVersionNo ?? doc.versionCount ?? 1}
                          </div>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <div className="text-xs text-[#222222]">{doc.departmentName || '—'}</div>
                          <div className="text-xs text-[#717171]">
                            {doc.businessCategoryName || '—'}
                          </div>
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
                          <Badge variant={getStatusVariant(doc.status)}>
                            {formatDocumentStatusLabel(doc.status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          <div className="inline-flex items-center justify-end gap-1">
                            {doc.status === 'DRAFT' && canClassify && (
                              <InteractiveHoverButton
                                variant="primary"
                                size="sm"
                                text="Kích hoạt"
                                icon={
                                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                                }
                                isLoading={isActivating}
                                disabled={isActivating}
                                onClick={() => onActivate(doc)}
                              />
                            )}
                            {doc.status === 'ACTIVE' &&
                              canView &&
                              (precheck.blocked && precheck.requiresMfa ? (
                                <Link
                                  href={mfaActionHref}
                                  title={precheck.reason ?? undefined}
                                  className="inline-flex min-h-8 items-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 py-1.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
                                >
                                  <ShieldCheck
                                    size={16}
                                    strokeWidth={1.75}
                                    className="text-[#E07912]"
                                    aria-hidden="true"
                                  />
                                  <span>Cần MFA</span>
                                </Link>
                              ) : (
                                <InteractiveHoverButton
                                  variant="secondary"
                                  size="sm"
                                  text="Xem"
                                  icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                                  onClick={() => onOpenPreview(doc)}
                                  isLoading={isOpening}
                                  disabled={
                                    isLoadingPreview || Boolean(openingDocId) || precheck.blocked
                                  }
                                  title={precheck.reason ?? undefined}
                                />
                              ))}
                            {doc.status === 'ACTIVE' && doc.allowDownload && canDownload && (
                              <InteractiveHoverButton
                                variant="secondary"
                                size="sm"
                                text="Tải"
                                icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                                onClick={() => onDownload(doc)}
                                disabled={isDocDownloading(doc.id) || precheck.blocked}
                                isLoading={isDocDownloading(doc.id)}
                                title={precheck.reason ?? undefined}
                              />
                            )}
                            {renderLifecycleIconButtons(doc, false)}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {onLoadDocsPage && (docsPage > 1 || docsHasMore || documents.length > 0) && (
          <div className="px-4 py-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
            <span>
              Hiển thị <strong className="text-[#222222]">{documents.length}</strong> tài liệu
            </span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={docsPage <= 1 || isLoadingDocs}
                onClick={() => onLoadDocsPage(Math.max(1, docsPage - 1))}
              />
              <span className="font-semibold text-[#222222] whitespace-nowrap tabular-nums">
                Trang {docsPage}
              </span>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={!docsHasMore || isLoadingDocs}
                onClick={() => onLoadDocsPage(docsPage + 1)}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
