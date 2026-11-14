'use client';

import Link from 'next/link';
import {
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

const QUICK_ROLES = [
  { name: 'Chủ sở hữu', href: '/owner', icon: FileText, color: 'text-[#008489]' },
  { name: 'Người đọc', href: '/reader', icon: Eye, color: 'text-[#008A05]' },
  { name: 'Sĩ quan SOC', href: '/security', icon: ShieldAlert, color: 'text-[#C13515]' },
  { name: 'Kiểm toán viên', href: '/auditor', icon: ClipboardCheck, color: 'text-[#008489]' },
  { name: 'Quản trị viên', href: '/admin', icon: Settings, color: 'text-[#E31C5F]' },
] as const;

interface HomeMobileDrawerProps {
  onClose: () => void;
}

/**
 * Thuật toán: Ngăn Kéo Điều Hướng Di Động Phản Hồi `375px` (`HomeMobileDrawer`)
 * Mục đích: Hiển thị lối tắt trang giới thiệu và 5 cổng vai trò với vùng chạm `>= 44x44px` và độ tương phản đạt chuẩn WCAG AA.
 */
export function HomeMobileDrawer({ onClose }: HomeMobileDrawerProps) {
  return (
    <div className="fixed inset-0 top-14 z-50 md:hidden">
      <div
        className="fixed inset-0 top-14 bg-[#222222]/25 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      <nav
        className="relative border-b border-[#ebebeb] bg-[#ffffff] p-4 shadow-xl animate-fade-in-down max-h-[calc(100dvh-3.5rem)] overflow-y-auto"
        aria-label="Điều hướng di động"
      >
        <div className="space-y-1">
          <div className="px-2 pb-2 text-xs font-semibold uppercase tracking-wider text-[#717171]">
            Nội dung hệ thống
          </div>
          <a
            href="#vai-tro"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <FileText
                size={16}
                strokeWidth={1.75}
                className="text-[#008489]"
                aria-hidden="true"
              />
              <span>Không gian làm việc theo vai trò</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>

          <a
            href="#kien-truc"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <Lock size={16} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
              <span>Kiến trúc an ninh đa tầng</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>

          <a
            href="#tieu-chuan"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <CheckCircle2
                size={16}
                strokeWidth={1.75}
                className="text-[#008A05]"
                aria-hidden="true"
              />
              <span>Tiêu chuẩn tuân thủ &amp; pháp lý</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>
        </div>

        <div className="mt-4 pt-4 border-t border-[#ebebeb]">
          <div className="px-2 pb-2 text-xs font-semibold uppercase tracking-wider text-[#717171]">
            Cổng truy cập vai trò
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {QUICK_ROLES.map((role) => {
              const Icon = role.icon;
              return (
                <Link
                  key={role.name}
                  href={role.href}
                  onClick={onClose}
                  className="flex min-h-11 items-center gap-2 rounded-full border border-[#ebebeb] bg-[#ffffff] px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
                >
                  <Icon size={16} strokeWidth={1.75} className={role.color} aria-hidden="true" />
                  <span className="truncate">{role.name}</span>
                </Link>
              );
            })}
          </div>
        </div>

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
            className="w-full min-h-11 text-xs"
            onClick={onClose}
          />
        </div>
      </nav>
    </div>
  );
}
