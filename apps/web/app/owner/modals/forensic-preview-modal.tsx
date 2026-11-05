'use client';

import { ShieldCheck, FileType, RefreshCw, QrCode, ChevronLeft, ChevronRight } from 'lucide-react';
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
  userFullName,
  username,
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
            <DialogDescription className="text-[11px] text-[#717171] mt-0.5 flex flex-wrap items-center gap-2">
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
            <div className="relative w-full max-w-2xl aspect-[3/4] bg-white rounded shadow-2xl p-8 flex flex-col justify-between overflow-hidden select-none border border-[#dddddd]">
              <div className="space-y-4 text-[#222222]">
                <div className="border-b border-[#ebebeb] pb-3">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-[#717171]">
                    CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM
                  </div>
                  <div className="text-xs font-semibold text-[#222222] mt-1">{document?.title}</div>
                  <div className="text-[10px] text-[#717171] font-bold mt-0.5">
                    Số: {document?.documentCode || 'DOC-CONFIDENTIAL-2026'}
                  </div>
                </div>

                <div className="space-y-2 text-xs leading-relaxed text-[#717171]">
                  <p>
                    Căn cứ quy chế an toàn thông tin và bảo vệ tài liệu mật số 14/QC-BCĐ, nội dung
                    này chỉ được phép tiếp cận bởi nhân sự được ủy quyền thông qua phiên làm việc đã
                    xác thực.
                  </p>
                  <p>
                    Nghiêm cấm sao chép, chụp ảnh màn hình hoặc phát tán ra ngoài phạm vi quy định.
                    Mọi vi phạm sẽ được xử lý theo quy định của pháp luật và truy vết qua mã
                    watermark định danh phiên.
                  </p>
                </div>
              </div>

              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] opacity-25">
                <div className="font-bold text-center text-[#C13515] text-sm leading-tight space-y-1">
                  <div>
                    {userFullName || 'CHỦ SỞ HỮU'} · {username}
                  </div>
                  <div>{new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC</div>
                  <div className="text-xs text-[#222222]">{document?.documentCode}</div>
                  <div className="text-[11px] text-[#008A05]">WM-{sessionId?.slice(0, 16)}</div>
                </div>
                <QrCode
                  size={24}
                  strokeWidth={1.75}
                  className="mt-2 text-[#C13515]"
                  aria-hidden="true"
                />
              </div>

              <div className="text-[10px] font-bold text-[#717171] flex justify-between border-t border-[#ebebeb] pt-2">
                <span>Phân hệ Owner · Controlled Delivery</span>
                <span>
                  Trang {page} / {totalPages}
                </span>
              </div>
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
