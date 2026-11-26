'use client';

import React, { useState } from 'react';
import { AppHeader } from './app-header';
import { AppSidebar } from './app-sidebar';
import { AppFooter } from './app-footer';

/**
 * Thuật toán: Khung Bố Cục Không Gian Làm Việc Khóa Chiều Cao Khung Nhìn & Chuyển Tiếp Tiêu Điểm (`AppLayout`)
 * Mục đích:
 *   - Cố định chiều cao vỏ ứng dụng ở `lg:h-dvh lg:max-h-dvh lg:overflow-hidden` trên màn hình lớn để `AppHeader`, `AppSidebar` (cùng cụm liên kết đáy) và `AppFooter` luôn neo vững chắc, không bị kéo giãn hay xô lệch khi bảng nhật ký/dữ liệu dài hàng trăm dòng.
 *   - Giữ cuộn tự nhiên `min-h-dvh overflow-x-hidden` trên thiết bị di động `375px` và kết nối liên kết trợ năng `skip-to-content` tới vùng `<main id="main-content">`.
 */
export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex min-h-dvh lg:h-dvh lg:max-h-dvh lg:overflow-hidden flex-col bg-[#f7f7f7] text-[#222222] antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F]">
      <a href="#main-content" className="skip-to-content">
        Chuyển đến nội dung chính
      </a>
      <AppHeader isSidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
      <div className="flex min-h-0 flex-1 overflow-x-hidden lg:overflow-hidden">
        <AppSidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <main
          id="main-content"
          tabIndex={-1}
          className="min-h-0 flex-1 min-w-0 overflow-x-hidden lg:overflow-y-auto px-3.5 py-3.5 sm:px-6 sm:py-5 lg:px-7 focus:outline-none"
        >
          <div className="mx-auto max-w-7xl min-w-0 page-enter">{children}</div>
        </main>
      </div>
      <AppFooter />
    </div>
  );
}
