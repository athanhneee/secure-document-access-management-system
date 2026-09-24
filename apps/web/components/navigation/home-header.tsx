'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Menu,
  X,
  FileText,
  Lock,
  CheckCircle2,
  ArrowRight,
  Eye,
  ShieldAlert,
  ClipboardCheck,
  Settings,
} from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const quickRoles = [
  { name: 'Chủ sở hữu', href: '/owner', icon: FileText, color: 'text-[#008489]' },
  { name: 'Người đọc', href: '/reader', icon: Eye, color: 'text-[#008A05]' },
  { name: 'Sĩ quan SOC', href: '/security', icon: ShieldAlert, color: 'text-[#E07912]' },
  { name: 'Kiểm toán viên', href: '/auditor', icon: ClipboardCheck, color: 'text-[#008489]' },
  { name: 'Quản trị viên', href: '/admin', icon: Settings, color: 'text-[#FF385C]' },
];

export function HomeHeader() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Close mobile menu on ESC key
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape' && mobileMenuOpen) {
        setMobileMenuOpen(false);
      }
    }
    if (mobileMenuOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [mobileMenuOpen]);

  function closeMenu() {
    setMobileMenuOpen(false);
  }

  return (
    <>
      <header className="sticky top-0 z-40 border-b border-[#ebebeb] bg-[#ffffff]/90 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          {/* Logo brand */}
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2 transition-opacity hover:opacity-90"
              aria-label="Trang chủ Hệ thống Quản lý Tài liệu Mật"
              onClick={closeMenu}
            >
              <ShieldCheck
                size={22}
                strokeWidth={1.75}
                className="text-[#FF385C] shrink-0"
                aria-hidden="true"
              />
              <div className="flex flex-col">
                <span className="text-sm font-extrabold tracking-tight text-[#222222]">
                  Secure<span className="font-light text-[#FF385C]">Document</span>
                </span>
                <span className="text-[9px] sm:text-[10px] text-[#717171] font-bold tracking-wider">
                  ENTERPRISE v1.0
                </span>
              </div>
            </Link>
          </div>

          {/* Desktop Navigation Links */}
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

          {/* Right Action Area */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Status Indicator (visible on tablet+) */}
            <div className="hidden sm:inline-flex items-center gap-1.5 text-xs font-semibold text-[#008A05]">
              <span className="dot dot-success animate-pulse" aria-hidden="true" />
              <span>Zero-Trust Active</span>
            </div>

            {/* Desktop Login Button */}
            <div className="hidden md:block">
              <InteractiveHoverButton
                href="/login"
                text="Đăng nhập hệ thống"
                className="h-8 px-4 text-xs font-semibold"
              />
            </div>

            {/* Mobile Quick Login Button */}
            <div className="md:hidden">
              <Link
                href="/login"
                className="inline-flex items-center justify-center h-8 px-3 rounded-full bg-[#FF385C] hover:bg-[#E0294C] text-xs font-semibold text-white active:scale-95 transition-all shadow-2xs"
                onClick={closeMenu}
              >
                Đăng nhập
              </Link>
            </div>

            {/* Mobile Hamburger Toggle Button */}
            <button
              type="button"
              className="flex h-8 w-8 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] active:scale-95 transition-all md:hidden cursor-pointer shadow-2xs"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label={mobileMenuOpen ? 'Đóng menu' : 'Mở menu điều hướng'}
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? (
                <X size={18} strokeWidth={2} />
              ) : (
                <Menu size={18} strokeWidth={2} />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Drawer Menu Overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 top-14 z-50 md:hidden">
          {/* Backdrop */}
          <div
            className="fixed inset-0 top-14 bg-black/25 backdrop-blur-xs transition-opacity"
            onClick={closeMenu}
            aria-hidden="true"
          />

          {/* Drawer content */}
          <nav
            className="relative border-b border-[#ebebeb] bg-[#ffffff] p-5 shadow-xl animate-fade-in-down max-h-[calc(100vh-3.5rem)] overflow-y-auto"
            aria-label="Điều hướng di động"
          >
            {/* Quick Navigation Links */}
            <div className="space-y-1">
              <div className="px-2 pb-2 text-[11px] font-semibold uppercase tracking-wider text-[#717171]">
                Nội dung hệ thống
              </div>
              <a
                href="#vai-tro"
                onClick={closeMenu}
                className="flex items-center justify-between rounded-[20px] px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
              >
                <span className="flex items-center gap-2.5">
                  <FileText size={16} strokeWidth={1.75} className="text-[#008489]" />
                  <span>Không gian làm việc theo vai trò</span>
                </span>
                <ArrowRight size={14} className="text-[#b0b0b0]" />
              </a>

              <a
                href="#kien-truc"
                onClick={closeMenu}
                className="flex items-center justify-between rounded-[20px] px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
              >
                <span className="flex items-center gap-2.5">
                  <Lock size={16} strokeWidth={1.75} className="text-[#FF385C]" />
                  <span>Kiến trúc an ninh đa tầng</span>
                </span>
                <ArrowRight size={14} className="text-[#b0b0b0]" />
              </a>

              <a
                href="#tieu-chuan"
                onClick={closeMenu}
                className="flex items-center justify-between rounded-[20px] px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
              >
                <span className="flex items-center gap-2.5">
                  <CheckCircle2 size={16} strokeWidth={1.75} className="text-[#008A05]" />
                  <span>Tiêu chuẩn tuân thủ & pháp lý</span>
                </span>
                <ArrowRight size={14} className="text-[#b0b0b0]" />
              </a>
            </div>

            {/* Quick Role Shortcuts */}
            <div className="mt-4 pt-4 border-t border-[#ebebeb]">
              <div className="px-2 pb-2 text-[11px] font-semibold uppercase tracking-wider text-[#717171]">
                Cổng truy cập vai trò
              </div>
              <div className="grid grid-cols-2 gap-2">
                {quickRoles.map((role) => {
                  const Icon = role.icon;
                  return (
                    <Link
                      key={role.name}
                      href={role.href}
                      onClick={closeMenu}
                      className="flex items-center gap-2 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
                    >
                      <Icon size={16} strokeWidth={1.75} className={role.color} />
                      <span className="truncate">{role.name}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Security Status & CTA Button */}
            <div className="mt-5 pt-4 border-t border-[#ebebeb] space-y-3">
              <div className="flex items-center justify-between px-1 text-xs text-[#717171]">
                <span>Trạng thái kiến trúc:</span>
                <span className="inline-flex items-center gap-1.5 font-semibold text-[#008A05]">
                  <span className="dot dot-success animate-pulse" aria-hidden="true" />
                  <span>Zero-Trust Active</span>
                </span>
              </div>

              <InteractiveHoverButton
                href="/login"
                variant="solid"
                text="Bắt đầu phiên làm việc"
                className="w-full h-10 text-xs"
                onClick={closeMenu}
              />
            </div>
          </nav>
        </div>
      )}
    </>
  );
}
