'use client';

import {
  ShieldCheck,
  ShieldAlert,
  FileType,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import type { useReaderViewer } from '../hooks/use-reader-viewer';

interface DocumentViewerModalProps {
  viewer: ReturnType<typeof useReaderViewer>;
  userFullName?: string | null | undefined;
  username?: string | null | undefined;
}

export function DocumentViewerModal({ viewer }: DocumentViewerModalProps) {
  const {
    previewOpen,
    previewDoc,
    previewSessionId,
    previewPdfUrl,
    previewPage,
    previewTotalPages,
    isLoadingPreview,
    handleClosePreview,
    handlePageChange,
  } = viewer;

  return (
    <Dialog open={previewOpen} onOpenChange={handleClosePreview}>
      <DialogContent className="max-w-4xl max-h-[92vh] flex flex-col border-[#ebebeb] bg-[#f7f7f7] text-[#222222] p-0 overflow-hidden">
        <DialogHeader className="p-4 border-b border-[#ebebeb] bg-[#ffffff] flex flex-row items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck
                size={16}
                strokeWidth={1.75}
                className="text-[#008A05]"
                aria-hidden="true"
              />
              <DialogTitle className="text-sm font-semibold text-[#222222]">
                Sandbox Xem Trước An Toàn: {previewDoc?.title}
              </DialogTitle>
            </div>
            <DialogDescription className="text-xs text-[#717171] mt-0.5 flex flex-wrap items-center gap-2">
              <span>Phiên: {previewSessionId || 'sess-active'}</span>
              <span className="text-[#ebebeb]">|</span>
              <span className="inline-flex items-center gap-1 text-[#008489] font-medium">
                <FileType size={16} strokeWidth={1.75} aria-hidden="true" /> Pipeline Gotenberg:
                Office (.docx/.xlsx/.pptx) &rarr; Watermarked PDF
              </span>
            </DialogDescription>
          </div>

          {previewDoc && <ClassificationBadge level={previewDoc.classificationCode} size="sm" />}
        </DialogHeader>

        <div className="relative flex-1 bg-[#f7f7f7] flex flex-col items-center justify-center p-4 overflow-hidden min-h-[480px]">
          {isLoadingPreview ? (
            <div className="flex flex-col items-center gap-3">
              {/* CONFLICT-RESOLVED: Chuẩn hóa icon tải và QR về tối đa 24px không bọc hộp nền/viền (rules/ui-design-system.md §2) */}
              <RefreshCw
                size={24}
                strokeWidth={1.75}
                className="animate-spin text-[#FF385C]"
                aria-hidden="true"
              />
              <p className="text-xs text-[#717171]">
                Đang chuyển đổi tệp Office sang PDF và đóng dấu Watermark…
              </p>
            </div>
          ) : previewPdfUrl ? (
            <div className="w-full flex-1 flex flex-col items-center justify-center min-h-[500px]">
              <iframe
                src={`${previewPdfUrl}#toolbar=0&navpanes=0`}
                className="w-full h-[520px] rounded border border-[#dddddd] bg-white shadow-sm"
                title={previewDoc?.title || 'Preview tài liệu'}
              />
            </div>
          ) : (
            <div
              role="alert"
              className="w-full max-w-md bg-[#ffffff] rounded-xl border border-[#dddddd] p-6 flex flex-col items-center text-center gap-3"
            >
              {/* CONFLICT-RESOLVED: Gỡ bỏ hoàn toàn trang văn bản giả gắn quốc hiệu/số hiệu khi thiếu previewPdfUrl để đảm bảo Fail-Closed (CRIT-07). */}
              <ShieldAlert
                size={24}
                strokeWidth={1.75}
                className="text-[#C13515]"
                aria-hidden="true"
              />
              <p className="text-sm font-semibold text-[#222222]">
                Không thể hiển thị bản xem trước PDF đã xác thực
              </p>
              <p className="text-xs leading-relaxed text-[#717171]">
                Luồng dữ liệu PDF gắn dấu Watermark chưa sẵn sàng hoặc không vượt qua bước kiểm định
                chữ ký tệp (chế độ bảo vệ Fail-Closed).
              </p>
            </div>
          )}
        </div>

        <div className="p-3 border-t border-[#ebebeb] bg-[#ffffff] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={previewPage <= 1 || isLoadingPreview}
              onClick={() => void handlePageChange(previewPage - 1)}
            />
            <span className="text-xs font-bold text-[#717171]">
              Trang {previewPage} / {previewTotalPages}
            </span>
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={previewPage >= previewTotalPages || isLoadingPreview}
              onClick={() => void handlePageChange(previewPage + 1)}
            />
          </div>

          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Đóng Sandbox"
            onClick={() => handleClosePreview(false)}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
