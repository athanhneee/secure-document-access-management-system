'use client';

import React, { useState } from 'react';
import { AppHeader } from './app-header';
import { AppSidebar } from './app-sidebar';
import { AppFooter } from './app-footer';

/**
 * Thuật toán: Khung Bố Cục Không Gian Làm Việc Phân Quyền & Chuyển Tiếp Tiêu Điểm Bỏ Qua (`AppLayout`)
 * Mục đích: Kết nối liên kết trợ năng `skip-to-content` tới vùng `<main id="main-content">`, đồng bộ trạng thái đóng/mở ngăn kéo di động giữa `AppHeader` và `AppSidebar`.
 */
export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex min-h-screen flex-col bg-[#f7f7f7] text-[#222222] antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F]">
      <a href="#main-content" className="skip-to-content">
        Chuyển đến nội dung chính
      </a>
      <AppHeader isSidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
      <div className="flex flex-1 overflow-hidden">
        <AppSidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 overflow-y-auto px-4 py-5 sm:px-6 sm:py-6 lg:px-8 focus:outline-none"
        >
          <div className="mx-auto max-w-7xl page-enter">{children}</div>
        </main>
      </div>
      <AppFooter />
    </div>
  );
}
