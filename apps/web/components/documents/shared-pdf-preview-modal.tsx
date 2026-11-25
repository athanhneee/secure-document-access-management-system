'use client';

import {
  ChevronLeft,
  ChevronRight,
  FileType,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { ClassificationBadge, type ClassificationCode } from '@/components/classification-badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface SharedPdfPreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string | null | undefined;
  classificationCode: ClassificationCode | null | undefined;
  sessionId: string | null;
  pdfUrl: string | null;
  page: number;
  totalPages: number;
  isLoading: boolean;
  pipelineLabel?: string | undefined;
  loadingLabel?: string | undefined;
  onPageChange: (newPage: number) => void;
}

/**
 * Thuật toán: Khung Xem Tài Liệu Bảo Mật Gắn Watermark Thích Ứng Di Động `375x667` (`SharedPdfPreviewModal`)
 * Mục đích: Hợp nhất trình xem trực tuyến bảo mật cho Chủ sở hữu và Người đọc, giới hạn chiều cao khung nhúng theo `dvh` (`h-[48dvh] sm:h-[60dvh]`) để thanh chuyển trang luôn hiển thị đầy đủ trên màn hình nhỏ và chỉ hiển thị mã phiên thực sau khi máy chủ cấp phát.
 */
export function SharedPdfPreviewModal({
  open,
  onOpenChange,
  title,
  classificationCode,
  sessionId,
  pdfUrl,
  page,
  totalPages,
  isLoading,
  pipelineLabel = 'Chế độ xem bảo mật · Có gắn watermark bảo mật',
  loadingLabel = 'Đang chuẩn bị trang tài liệu và gắn watermark bảo mật…',
  onPageChange,
}: SharedPdfPreviewModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90dvh] flex flex-col border-[#ebebeb] bg-[#f7f7f7] text-[#222222] p-0 overflow-hidden">
        <DialogHeader className="mb-0 p-4 pr-14 border-b border-[#ebebeb] bg-[#ffffff] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
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
            <DialogDescription className="text-xs text-[#717171] mt-0.5 flex flex-wrap items-center gap-2">
              <span>
                {sessionId ? 'Phiên xem bảo mật đang hoạt động' : 'Đang khởi tạo phiên truy cập…'}
              </span>
              <span className="text-[#ebebeb]" aria-hidden="true">
                |
              </span>
              <span className="inline-flex items-center gap-1 text-[#008489] font-medium">
                <FileType size={16} strokeWidth={1.75} aria-hidden="true" />
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

        <div className="relative flex-1 bg-[#f7f7f7] flex flex-col items-center justify-center p-3 sm:p-4 overflow-y-auto min-h-[240px]">
          {isLoading ? (
            <div className="flex flex-col items-center gap-3 text-center">
              <RefreshCw
                size={24}
                strokeWidth={1.75}
                className="animate-spin text-[#FF385C]"
                aria-hidden="true"
              />
              <p className="text-xs text-[#717171]">{loadingLabel}</p>
            </div>
          ) : pdfUrl ? (
            <div className="w-full flex-1 flex flex-col items-center justify-center min-h-[240px]">
              <iframe
                src={`${pdfUrl}#toolbar=0&navpanes=0`}
                className="h-[48dvh] sm:h-[60dvh] max-h-[540px] min-h-[240px] w-full rounded border border-[#dddddd] bg-white shadow-sm"
                title={title || 'Xem trước tài liệu'}
              />
            </div>
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
                Bản xem trước có gắn watermark bảo mật hiện chưa sẵn sàng hoặc không hợp lệ. Vui
                lòng thử lại hoặc kiểm tra quyền truy cập của bạn.
              </p>
            </div>
          )}
        </div>

        <div className="p-3 border-t border-[#ebebeb] bg-[#ffffff] flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={page <= 1 || isLoading}
              onClick={() => onPageChange(Math.max(1, page - 1))}
            />
            <span className="text-xs font-bold text-[#717171] px-1">
              Trang {page} / {totalPages}
            </span>
            <InteractiveHoverButton
              size="sm"
              variant="secondary"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={page >= totalPages || isLoading}
              onClick={() => onPageChange(Math.min(totalPages, page + 1))}
            />
          </div>

          <InteractiveHoverButton
            size="sm"
            variant="secondary"
            text="Đóng"
            onClick={() => onOpenChange(false)}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
