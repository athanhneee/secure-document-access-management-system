'use client';

/**
 * Thuật toán: Chân Trang Nhận Diện Thương Hiệu Chuẩn Production (`AppFooter`)
 * Mục đích: Hiển thị đồng bộ tên hệ thống `SecureDocument` và thông tin bản quyền gọn gàng trên mọi kích thước màn hình (bao gồm `375px`), không để lộ thông số kiến trúc hay thuật toán bảo mật nội bộ.
 */
import { ShieldCheck } from 'lucide-react';

export function AppFooter() {
  return (
    <footer className="w-full border-t border-[#ebebeb] bg-[#ffffff] px-4 py-2.5 text-xs text-[#717171] sm:px-6">
      <div className="mx-auto flex flex-col items-center justify-between gap-2 sm:flex-row max-w-7xl">
        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <div className="flex items-center gap-1.5 font-medium text-[#222222]">
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className="text-[#008A05]"
              aria-hidden="true"
            />
            <span>
              Secure<span className="font-light text-[#E31C5F]">Document</span>
            </span>
          </div>
          <span className="hidden sm:inline text-[#ebebeb]">·</span>
          <span className="text-xs text-[#717171]">
            Hệ thống quản lý truy cập tài liệu mật nội bộ
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-[#717171]">
          <span>© 2026 SecureDocument</span>
        </div>
      </div>
    </footer>
  );
}
