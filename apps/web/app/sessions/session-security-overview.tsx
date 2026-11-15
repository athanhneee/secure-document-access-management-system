'use client';

/**
 * Thuật toán: Tổng Quan Bảo Mật Phiên Hiện Tại & Chính Sách Zero-Trust (`SessionSecurityOverview`)
 * Mục đích: Trình bày thông số bảo vệ Cookie `HttpOnly · SameSite=Strict`, cơ chế CSRF Double-Submit và trạng thái nâng cấp MFA `staff-001` của thiết bị hiện hành.
 */
import { Laptop, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface SessionSecurityOverviewProps {
  fullName?: string | undefined;
  username?: string | undefined;
  mfaVerified?: boolean | undefined;
  onLogoutCurrent: () => void;
}

export function SessionSecurityOverview({
  fullName,
  username,
  mfaVerified,
  onLogoutCurrent,
}: SessionSecurityOverviewProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Laptop
                size={20}
                strokeWidth={1.75}
                className="text-[#008A05] shrink-0"
                aria-hidden="true"
              />
              <CardTitle className="text-sm font-bold text-[#222222]">
                Phiên hiện tại (Thiết bị này)
              </CardTitle>
            </div>
            <Badge variant="success">Active</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-[#222222]">
          <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2">
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Người dùng</span>
              <span className="font-semibold text-[#222222]">
                {fullName} ({username})
              </span>
            </div>
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Xác thực đa yếu tố</span>
              <Badge variant={mfaVerified ? 'success' : 'warning'}>
                {mfaVerified ? 'Đã xác thực MFA' : 'Chưa xác thực MFA'}
              </Badge>
            </div>
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Bảo mật Cookie</span>
              <span className="font-mono text-[#008A05]">HttpOnly · SameSite=Strict</span>
            </div>
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Phòng chống CSRF</span>
              <span className="font-mono text-[#008A05]">Double-Submit (sda_csrf)</span>
            </div>
          </div>
        </CardContent>
        <CardFooter className="pt-3 border-t border-[#ebebeb] flex justify-end">
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            onClick={onLogoutCurrent}
            text="Đăng xuất phiên này"
            className="w-full sm:w-auto"
          />
        </CardFooter>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={20}
              strokeWidth={1.75}
              className="text-[#008A05] shrink-0"
              aria-hidden="true"
            />
            <CardTitle className="text-sm font-bold text-[#222222]">
              Chính sách an toàn phiên
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-2.5 text-xs text-[#717171] leading-relaxed">
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Hết hạn tự động:</strong> Khóa phiên khi không hoạt
              động vượt ngưỡng cho phép.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Thu hồi tức thì:</strong> Ngắt mọi phiên đọc tài
              liệu ngay khi giấy phép truy cập bị thu hồi.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Chống phát lại:</strong> Xoay vòng Refresh Token tự
              động để phát hiện chiếm quyền phiên.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
