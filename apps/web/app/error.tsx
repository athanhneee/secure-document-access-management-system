'use client';

/**
 * Thuật toán: Ranh Giới Bắt Lỗi Runtime Chuẩn Tiếng Việt Không Lộ Chi Tiết Kỹ Thuật (`GlobalErrorPage`)
 * Mục đích: Bắt mọi ngoại lệ không mong muốn ở tầng ứng dụng Next.js App Router, hiển thị thông điệp thân thiện và nút thử lại mà không tiết lộ dấu vết ngăn xếp (`stack trace`) ra màn hình Production.
 */
import Link from 'next/link';
import { AlertTriangle, ArrowLeft, RefreshCw, ShieldCheck } from 'lucide-react';

export default function GlobalErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 text-[#222222] antialiased">
      <div className="w-full max-w-md rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-6 sm:p-8 text-center shadow-[0_8px_30px_rgba(0,0,0,0.05)] space-y-5">
        <div className="flex items-center justify-center gap-2 text-[#222222]">
          <ShieldCheck size={20} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
          <span className="text-sm font-bold tracking-tight">
            Secure<span className="font-light text-[#E31C5F]">Document</span>
          </span>
        </div>

        <div className="space-y-2">
          <div className="flex justify-center text-[#C13515]">
            <AlertTriangle size={24} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#222222]">
            Hệ thống tạm thời gặp sự cố
          </h1>
          <p className="text-xs text-[#717171] leading-relaxed">
            Không thể hiển thị nội dung vào lúc này. Vui lòng thử tải lại trang hoặc liên hệ bộ phận
            quản trị nếu sự cố tiếp diễn.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1">
          <button
            type="button"
            onClick={reset}
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full bg-[#FF385C] px-5 py-2 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors shadow-2xs cursor-pointer"
          >
            <RefreshCw size={16} strokeWidth={2} aria-hidden="true" />
            <span>Thử lại</span>
          </button>
          <Link
            href="/"
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-5 py-2 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
          >
            <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>Về trang chủ</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
