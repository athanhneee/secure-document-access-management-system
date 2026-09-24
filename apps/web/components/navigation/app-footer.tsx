'use client';

import { ShieldCheck, Lock, EyeOff, Hash } from 'lucide-react';

export function AppFooter() {
  return (
    <footer className="w-full border-t border-[#ebebeb] bg-[#ffffff] px-4 py-4 text-xs text-[#717171] sm:px-6">
      <div className="mx-auto flex flex-col items-center justify-between gap-3 sm:flex-row max-w-7xl">
        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          <div className="flex items-center gap-1.5 font-medium text-[#222222]">
            <ShieldCheck className="h-4 w-4 text-[#008A05]" aria-hidden="true" />
            <span>Secure Document Access System</span>
          </div>
          <span className="hidden sm:inline text-[#ebebeb]">·</span>
          <span className="flex items-center gap-1 text-[11px] text-[#717171]">
            <Lock className="h-3.5 w-3.5 text-[#E07912]" aria-hidden="true" />
            <span>Chính sách kiểm soát quyền tối thiểu (Least Privilege)</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-[11px] text-[#717171]">
          <span className="flex items-center gap-1">
            <Hash className="h-3.5 w-3.5 text-[#008489]" aria-hidden="true" />
            <span>HMAC-SHA256 Audit Trail</span>
          </span>
          <span className="text-[#ebebeb]">·</span>
          <span className="flex items-center gap-1">
            <EyeOff className="h-3.5 w-3.5 text-[#FF385C]" aria-hidden="true" />
            <span>Watermark định danh phiên</span>
          </span>
        </div>
      </div>
    </footer>
  );
}
