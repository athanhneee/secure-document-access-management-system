'use client';

import { useEffect, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  FileLock2,
  Loader2,
  Maximize2,
  Minimize2,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { ClassificationBadge, type ClassificationCode } from '@/components/classification-badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { SecurePdfCanvasViewer } from './secure-pdf-canvas-viewer';

export interface SharedPdfPreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string | null | undefined;
  classificationCode: ClassificationCode | null | undefined;
  sessionId: string | null;
  pdfBytes?: Uint8Array | null | undefined;
  pdfUrl?: string | null | undefined;
  page: number;
  totalPages: number;
  isLoading: boolean;
  allowDownload?: boolean | undefined;
  versionNo?: number | null | undefined;
  obligations?: readonly string[] | undefined;
  pageError?: string | null | undefined;
  onRetryPage?: (() => void) | undefined;
  pipelineLabel?: string | undefined;
  loadingLabel?: string | undefined;
  onPageChange: (newPage: number) => void;
}

/**
 * Thuật toán: Khung Xem Tài Liệu Bảo Mật Gắn Watermark Trên Canvas Đa Nền Tảng `375x667` (`SharedPdfPreviewModal`)
 * Mục đích:
 *   - Hợp nhất trình xem trực tuyến bảo mật cho Chủ sở hữu và Người đọc bằng `<canvas>` PDF.js (không dùng `iframe blob:`), chặn phím tắt lưu/in (`Ctrl+S`/`Ctrl+P`) khi `allowDownload === false` (`V-01`, `V-57`).
 *   - Hiển thị mã phiên rút gọn thực từ máy chủ, phiên bản tài liệu, điều khiển thu phóng/toàn màn hình/nhảy trang và thông báo lỗi chuyển trang nội tuyến không đóng sập trình xem (`V-07`, `V-44`, `V-53`, `V-56`, `V-63`).
 */
export function SharedPdfPreviewModal(props: SharedPdfPreviewModalProps) {
  const { open, onOpenChange, sessionId } = props;
  const resetKey = `${open ? 'open' : 'closed'}:${sessionId ?? 'pending'}`;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <SharedPdfPreviewModalBody key={resetKey} {...props} /> : null}
    </Dialog>
  );
}

function SharedPdfPreviewModalBody({
  open,
  onOpenChange,
  title,
  classificationCode,
  sessionId,
  pdfBytes,
  page,
  totalPages,
  isLoading,
  allowDownload = false,
  versionNo,
  obligations = [],
  pageError,
  onRetryPage,
  pipelineLabel = 'Chế độ xem bảo mật · Có gắn watermark bảo mật',
  loadingLabel = 'Đang chuẩn bị trang tài liệu và gắn watermark bảo mật…',
  onPageChange,
}: SharedPdfPreviewModalProps) {
  const [zoomScale, setZoomScale] = useState(1);
  const [isExpanded, setIsExpanded] = useState(false);
  const [draftJump, setDraftJump] = useState<{ page: number; value: string } | null>(null);
  const [blockedShortcutNotice, setBlockedShortcutNotice] = useState<string | null>(null);
  const effectiveAllowDownload = Boolean(allowDownload) && !obligations.includes('FORBID_DOWNLOAD');

  const jumpInput = draftJump && draftJump.page === page ? draftJump.value : String(page);

  function handleDialogOpenChange(nextOpen: boolean) {
    onOpenChange(nextOpen);
  }

  useEffect(() => {
    if (!open) return;

    function handleKeyDown(e: KeyboardEvent) {
      const key = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && (key === 's' || key === 'p')) {
        if (!effectiveAllowDownload) {
          e.preventDefault();
          e.stopPropagation();
          setBlockedShortcutNotice(
            'Tài liệu này áp dụng chính sách Chỉ xem trực tuyến — lưu tệp và in ấn đã bị vô hiệu hóa.',
          );
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown, true);
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true);
    };
  }, [open, effectiveAllowDownload]);

  function commitPageJump() {
    const parsed = Number.parseInt(jumpInput.trim(), 10);
    if (!Number.isFinite(parsed)) {
      setDraftJump(null);
      return;
    }
    const clamped = Math.min(Math.max(1, parsed), Math.max(1, totalPages));
    setDraftJump(null);
    if (clamped !== page) {
      onPageChange(clamped);
    }
  }

  return (
    <DialogContent
      showContextError={false}
      className={`${isExpanded ? 'max-w-[96vw]' : 'max-w-4xl'} max-h-[92dvh] flex flex-col border-[#ebebeb] bg-[#f7f7f7] text-[#222222] p-0 overflow-hidden`}
    >
      <DialogHeader className="mb-0 p-3.5 sm:p-4 pr-14 border-b border-[#ebebeb] bg-[#ffffff] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#008A05]"
              aria-hidden="true"
            />
            <DialogTitle className="text-sm font-semibold text-[#222222] truncate">
              {title ? `Xem tài liệu bảo mật: ${title}` : 'Xem tài liệu bảo mật'}
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171] mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              {sessionId
                ? `Phiên xem bảo mật #${sessionId.slice(0, 8)}`
                : 'Đang khởi tạo phiên truy cập…'}
            </span>
            {typeof versionNo === 'number' && versionNo > 0 && (
              <>
                <span className="text-[#dddddd]" aria-hidden="true">
                  ·
                </span>
                <span>Phiên bản v{versionNo}</span>
              </>
            )}
            <span className="text-[#dddddd]" aria-hidden="true">
              |
            </span>
            <span className="inline-flex items-center gap-1 text-[#008489] font-medium">
              <FileLock2 size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>{pipelineLabel}</span>
            </span>
          </DialogDescription>
        </div>

        {classificationCode && (
          <div className="shrink-0 self-start sm:self-center">
            <ClassificationBadge level={classificationCode} size="sm" />
          </div>
        )}
      </DialogHeader>

      <div className="px-3.5 py-2 border-b border-[#ebebeb] bg-[#ffffff] flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setZoomScale((z) => Math.max(0.6, Math.round((z - 0.2) * 10) / 10))}
            disabled={zoomScale <= 0.6 || isLoading}
            aria-label="Thu nhỏ trang tài liệu"
            className="flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] disabled:opacity-40 cursor-pointer"
          >
            <ZoomOut size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
          <span className="min-w-12 text-center font-semibold text-[#222222]">
            {Math.round(zoomScale * 100)}%
          </span>
          <button
            type="button"
            onClick={() => setZoomScale((z) => Math.min(2.4, Math.round((z + 0.2) * 10) / 10))}
            disabled={zoomScale >= 2.4 || isLoading}
            aria-label="Phóng to trang tài liệu"
            className="flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] disabled:opacity-40 cursor-pointer"
          >
            <ZoomIn size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
          <button
            type="button"
            onClick={() => setZoomScale(1)}
            disabled={zoomScale === 1 || isLoading}
            aria-label="Khôi phục tỷ lệ khớp chiều rộng"
            className="flex h-11 w-11 sm:h-8 sm:w-8 items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] disabled:opacity-40 cursor-pointer"
          >
            <RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded((prev) => !prev)}
          aria-label={isExpanded ? 'Thu gọn khung xem tài liệu' : 'Mở rộng khung xem tài liệu'}
          className="inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 py-1 text-xs font-medium text-[#222222] hover:bg-[#f7f7f7] cursor-pointer"
        >
          {isExpanded ? (
            <Minimize2 size={16} strokeWidth={1.75} aria-hidden="true" />
          ) : (
            <Maximize2 size={16} strokeWidth={1.75} aria-hidden="true" />
          )}
          <span className="hidden sm:inline">{isExpanded ? 'Thu gọn' : 'Mở rộng'}</span>
        </button>
      </div>

      <div
        onContextMenu={(e) => {
          if (!effectiveAllowDownload) e.preventDefault();
        }}
        className="relative flex-1 bg-[#f7f7f7] flex flex-col items-center justify-center p-3 sm:p-4 overflow-y-auto min-h-[260px] gap-2.5"
      >
        {blockedShortcutNotice && (
          <Alert variant="warning" className="w-full text-xs">
            <ShieldAlert
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2">{blockedShortcutNotice}</AlertDescription>
          </Alert>
        )}

        {pageError && (
          <Alert variant="destructive" className="w-full text-xs">
            <ShieldAlert
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <div className="ml-2 flex flex-wrap items-center justify-between gap-2 w-full">
              <AlertDescription>{pageError}</AlertDescription>
              {onRetryPage && (
                <InteractiveHoverButton
                  type="button"
                  size="sm"
                  variant="secondary"
                  text="Thử tải lại trang"
                  icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={onRetryPage}
                />
              )}
            </div>
          </Alert>
        )}

        {isLoading ? (
          <div className="flex flex-col items-center gap-3 text-center py-8">
            <Loader2
              size={24}
              strokeWidth={2}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <p className="text-xs text-[#717171]">{loadingLabel}</p>
          </div>
        ) : pdfBytes && pdfBytes.byteLength > 0 ? (
          <SecurePdfCanvasViewer
            pdfBytes={pdfBytes}
            zoomScale={zoomScale}
            allowDownload={effectiveAllowDownload}
            title={title}
          />
        ) : (
          <div
            role="alert"
            className="w-full max-w-md bg-[#ffffff] rounded-[20px] border border-[#dddddd] p-5 flex flex-col items-center text-center gap-3"
          >
            <ShieldAlert
              size={24}
              strokeWidth={1.75}
              className="text-[#C13515]"
              aria-hidden="true"
            />
            <p className="text-sm font-semibold text-[#222222]">
              Không thể hiển thị bản xem trước tài liệu
            </p>
            <p className="text-xs leading-relaxed text-[#717171]">
              Bản xem trước có gắn watermark bảo mật hiện chưa sẵn sàng hoặc không hợp lệ. Vui lòng
              thử lại hoặc kiểm tra quyền truy cập của bạn.
            </p>
          </div>
        )}
      </div>

      <div className="p-3 border-t border-[#ebebeb] bg-[#ffffff] flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {totalPages > 1 ? (
            <>
              <InteractiveHoverButton
                size="sm"
                variant="secondary"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page <= 1 || isLoading}
                onClick={() => onPageChange(Math.max(1, page - 1))}
              />
              <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#717171]">
                <label htmlFor="pdf-viewer-page-jump" className="sr-only">
                  Chuyển nhanh tới số trang
                </label>
                <span>Trang</span>
                <input
                  id="pdf-viewer-page-jump"
                  type="number"
                  min={1}
                  max={totalPages}
                  value={jumpInput}
                  disabled={isLoading}
                  onChange={(e) => setDraftJump({ page, value: e.target.value })}
                  onBlur={commitPageJump}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      commitPageJump();
                    }
                  }}
                  className="w-14 min-h-11 sm:min-h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-2 text-center text-xs font-bold text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15"
                />
                <span>/ {totalPages}</span>
              </div>
              <InteractiveHoverButton
                size="sm"
                variant="secondary"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page >= totalPages || isLoading}
                onClick={() => onPageChange(Math.min(totalPages, page + 1))}
              />
            </>
          ) : (
            <span className="text-xs font-semibold text-[#717171] px-1">
              Trang {page} / {totalPages}
            </span>
          )}
        </div>

        <InteractiveHoverButton
          size="sm"
          variant="secondary"
          text="Đóng"
          onClick={() => handleDialogOpenChange(false)}
        />
      </div>
    </DialogContent>
  );
}
