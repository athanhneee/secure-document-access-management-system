'use client';

/**
 * Thuật toán: Trình Hiển Thị Không Tràn Dòng & Xác Nhận Đã Lưu 10 Mã Khôi Phục Dùng Một Lần (`MfaRecoveryCodesCard`)
 * Mục đích: Dàn lưới `grid-cols-1 sm:grid-cols-2` kèm `break-all` và font mono gọn gàng trên màn hình `375px` để chuỗi mã khôi phục 22 ký tự không bao giờ bị cắt ngang trước khi chuyển vào không gian đặc quyền.
 */
import { Check, Copy, ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface MfaRecoveryCodesCardProps {
  recoveryCodes: string[];
  copied: boolean;
  isRedirecting: boolean;
  onCopyAll: () => void;
  onConfirmSaved: () => void;
}

export function MfaRecoveryCodesCard({
  recoveryCodes,
  copied,
  isRedirecting,
  onCopyAll,
  onConfirmSaved,
}: MfaRecoveryCodesCardProps) {
  return (
    <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)]">
      <CardHeader className="space-y-1 pb-3">
        <CardTitle className="text-base font-bold text-[#222222] flex items-center gap-2">
          <ShieldCheck size={20} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          <span>Lưu 10 mã khôi phục khẩn cấp</span>
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Mỗi mã chỉ dùng một lần khi mất thiết bị xác thực và sẽ không hiển thị lại sau bước này.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 font-mono text-xs font-semibold text-[#222222]">
          {recoveryCodes.map((code) => (
            <div
              key={code}
              className="min-w-0 break-all rounded-[12px] bg-[#ffffff] border border-[#ebebeb] px-3 py-2 text-center leading-snug tracking-tight select-all"
            >
              {code}
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={onCopyAll}
          className="w-full min-h-11 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-4 py-2 text-xs font-semibold text-[#222222] flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
        >
          {copied ? (
            <Check size={16} strokeWidth={2} className="text-[#008A05]" aria-hidden="true" />
          ) : (
            <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
          )}
          <span>{copied ? 'Đã sao chép toàn bộ 10 mã' : 'Sao chép tất cả mã khôi phục'}</span>
        </button>
        <InteractiveHoverButton
          type="button"
          variant="primary"
          isLoading={isRedirecting}
          disabled={isRedirecting}
          text="Tôi đã lưu mã khôi phục — Tiếp tục vào hệ thống"
          onClick={onConfirmSaved}
          className="w-full py-2.5 text-xs font-semibold"
        />
      </CardContent>
    </Card>
  );
}
