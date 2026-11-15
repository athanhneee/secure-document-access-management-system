'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, Menu, X } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { HomeMobileDrawer } from './home-mobile-drawer';

/**
 * Thuật toán: Thanh Đầu Đề Trang Giới Thiệu & Kích Hoạt Ngăn Kéo Phương Thức Di Động (`HomeHeader`)
 * Mục đích: Hiển thị nhận diện thương hiệu, lối tắt neo nội dung trên màn hình rộng và mở ngăn kéo `<dialog>.showModal()` (`HomeMobileDrawer`) trên thiết bị di động `375px`.
 */
export function HomeHeader() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  function closeMenu() {
    setMobileMenuOpen(false);
  }

  return (
    <>
      <header className="sticky top-0 z-40 border-b border-[#ebebeb] bg-[#ffffff]/90 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2 transition-opacity hover:opacity-90"
              aria-label="Trang chủ Hệ thống Quản lý Tài liệu Mật"
              onClick={closeMenu}
            >
              <ShieldCheck
                size={20}
                strokeWidth={1.75}
                className="text-[#E31C5F] shrink-0"
                aria-hidden="true"
              />
              <span className="text-sm font-bold tracking-tight text-[#222222]">
                Secure<span className="font-light text-[#E31C5F]">Document</span>
              </span>
            </Link>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-xs text-[#717171] font-medium">
            <a href="#vai-tro" className="hover:text-[#222222] transition-colors">
              Không gian làm việc
            </a>
            <a href="#kien-truc" className="hover:text-[#222222] transition-colors">
              Kiến trúc an ninh
            </a>
            <a href="#tieu-chuan" className="hover:text-[#222222] transition-colors">
              Tiêu chuẩn tuân thủ
            </a>
          </nav>

          <div className="flex items-center gap-2 sm:gap-3">
            <div className="staff-badge bg-transparent border-0 p-0 hidden sm:inline-flex items-center gap-1.5 text-xs font-semibold text-[#008A05]">
              <span className="dot dot-success animate-pulse" aria-hidden="true" />
              <span>Zero-Trust Active</span>
            </div>

            <div className="hidden md:block">
              <InteractiveHoverButton
                href="/login"
                text="Đăng nhập hệ thống"
                className="min-h-9 px-4 text-xs font-semibold"
              />
            </div>

            <div className="md:hidden">
              <Link
                href="/login"
                className="inline-flex min-h-11 items-center justify-center px-3.5 rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-xs font-semibold text-[#ffffff] active:scale-95 transition-all shadow-2xs"
                onClick={closeMenu}
              >
                Đăng nhập
              </Link>
            </div>

            <button
              type="button"
              className="flex h-11 w-11 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] active:scale-95 transition-all md:hidden cursor-pointer shadow-2xs"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label={mobileMenuOpen ? 'Đóng menu' : 'Mở menu điều hướng'}
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? (
                <X size={20} strokeWidth={2} aria-hidden="true" />
              ) : (
                <Menu size={20} strokeWidth={2} aria-hidden="true" />
              )}
            </button>
          </div>
        </div>
      </header>

      {mobileMenuOpen && <HomeMobileDrawer onClose={closeMenu} />}
    </>
  );
}
