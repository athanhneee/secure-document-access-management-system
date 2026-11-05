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
import type { DocumentItem } from '../types';

interface ForensicPreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  sessionId: string | null;
  pdfUrl: string | null;
  page: number;
  totalPages: number;
  isLoading: boolean;
  userFullName?: string | null | undefined;
  username?: string | null | undefined;
  onPageChange: (newPage: number) => void;
}

export function ForensicPreviewModal({
  open,
  onOpenChange,
  document,
  sessionId,
  pdfUrl,
  page,
  totalPages,
  isLoading,
  onPageChange,
}: ForensicPreviewModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
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
                Sandbox Xem Trước An Toàn: {document?.title}
              </DialogTitle>
            </div>
            <DialogDescription className="text-xs text-[#717171] mt-0.5 flex flex-wrap items-center gap-2">
              <span>Phiên: {sessionId || 'sess-active'}</span>
              <span className="text-[#ebebeb]">|</span>
              <span className="inline-flex items-center gap-1 text-[#008489] font-medium">
                <FileType size={16} strokeWidth={1.75} aria-hidden="true" /> Pipeline Gotenberg:
                Office &rarr; Watermarked PDF
              </span>
            </DialogDescription>
          </div>

          {document && <ClassificationBadge level={document.classificationCode} size="sm" />}
        </DialogHeader>

        <div className="relative flex-1 bg-[#f7f7f7] flex flex-col items-center justify-center p-4 overflow-hidden min-h-[480px]">
          {isLoading ? (
            <div className="flex flex-col items-center gap-3">
              {/* CONFLICT-RESOLVED: Chuẩn hóa icon tải và QR về tối đa 24px không bọc hộp nền/viền (rules/ui-design-system.md §2) */}
              <RefreshCw
                size={24}
                strokeWidth={1.75}
                className="animate-spin text-[#FF385C]"
                aria-hidden="true"
              />
              <p className="text-xs text-[#717171]">
                Đang xử lý trang tài liệu và nhúng dấu Watermark động…
              </p>
            </div>
          ) : pdfUrl ? (
            <div className="w-full flex-1 flex flex-col items-center justify-center min-h-[500px]">
              <iframe
                src={`${pdfUrl}#toolbar=0&navpanes=0`}
                className="w-full h-[520px] rounded border border-[#dddddd] bg-white shadow-sm"
                title={document?.title || 'Preview tài liệu'}
              />
            </div>
          ) : (
            <div
              role="alert"
              className="w-full max-w-md bg-[#ffffff] rounded-xl border border-[#dddddd] p-6 flex flex-col items-center text-center gap-3"
            >
              {/* CONFLICT-RESOLVED: Gỡ bỏ hoàn toàn trang văn bản giả gắn quốc hiệu/số hiệu khi thiếu pdfUrl để đảm bảo Fail-Closed (CRIT-07). */}
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
              disabled={page <= 1 || isLoading}
              onClick={() => onPageChange(Math.max(1, page - 1))}
            />
            <span className="text-xs font-bold text-[#717171]">
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
            text="Đóng Sandbox"
            onClick={() => onOpenChange(false)}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
