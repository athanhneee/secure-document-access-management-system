/**
 * Thuật toán: Trang Báo Lỗi 404 Chuẩn Tiếng Việt & Điều Hướng An Toàn Về Trang Chủ (`NotFoundPage`)
 * Mục đích: Thay thế trang 404 tiếng Anh mặc định của Next.js bằng thông điệp tiếng Việt rõ ràng, tuân thủ tuyệt đối bảng màu, biểu tượng Lucide và bố cục thích ứng `375px` của `rules/ui-design-system.md`.
 */
import Link from 'next/link';
import { ArrowLeft, FileSearch, ShieldCheck } from 'lucide-react';

export default function NotFoundPage() {
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
          <div className="flex justify-center text-[#717171]">
            <FileSearch size={24} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#222222]">
            Không tìm thấy trang yêu cầu
          </h1>
          <p className="text-xs text-[#717171] leading-relaxed">
            Đường dẫn bạn truy cập không tồn tại hoặc đã được thay đổi. Vui lòng kiểm tra lại địa
            chỉ hoặc quay về trang chủ hệ thống.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1">
          <Link
            href="/"
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full bg-[#FF385C] px-5 py-2 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors shadow-2xs"
          >
            <ArrowLeft size={16} strokeWidth={2} aria-hidden="true" />
            <span>Về trang chủ</span>
          </Link>
          <Link
            href="/login"
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] px-5 py-2 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
          >
            Đăng nhập hệ thống
          </Link>
        </div>
      </div>
    </div>
  );
}
