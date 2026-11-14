'use client';

import { Laptop, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface SessionSecurityOverviewProps {
  fullName?: string | undefined;
  username?: string | undefined;
  onLogoutCurrent: () => void;
}

/**
 * Thuật toán: Tổng Quan Bảo Mật Phiên Hiện Tại & Chính Sách Zero-Trust (`SessionSecurityOverview`)
 * Mục đích: Trình bày thông số bảo vệ Cookie `HttpOnly · SameSite=Strict`, cơ chế CSRF Double-Submit và quy tắc thu hồi tức thì.
 */
export function SessionSecurityOverview({
  fullName,
  username,
  onLogoutCurrent,
}: SessionSecurityOverviewProps) {
  return (
    <div className="grid gap-5 md:grid-cols-2">
      <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <Laptop
                size={20}
                strokeWidth={1.75}
                className="text-[#008A05] shrink-0"
                aria-hidden="true"
              />
              <div>
                <CardTitle className="text-sm font-bold text-[#222222]">
                  Phiên hiện tại (Thiết bị này)
                </CardTitle>
                <CardDescription className="text-xs text-[#008A05] font-medium">
                  Đang hoạt động · Được cấp quyền
                </CardDescription>
              </div>
            </div>
            <Badge variant="success">Active</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-[#222222]">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2.5">
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Người dùng:</span>
              <span className="font-semibold text-[#222222]">
                {fullName} ({username})
              </span>
            </div>
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Bảo mật Cookie:</span>
              <span className="font-bold text-[#008A05] text-xs">HttpOnly · SameSite=Strict</span>
            </div>
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Phòng chống CSRF:</span>
              <span className="font-bold text-[#008A05] text-xs">
                Double-Submit Cookie (sda_csrf)
              </span>
            </div>
          </div>
        </CardContent>
        <CardFooter className="pt-2 border-t border-[#ebebeb] flex justify-end">
          <InteractiveHoverButton
            variant="secondary"
            onClick={onLogoutCurrent}
            text="Đăng xuất phiên này"
            className="w-full sm:w-auto text-xs"
          />
        </CardFooter>
      </Card>

      <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2.5">
            <ShieldCheck
              size={20}
              strokeWidth={1.75}
              className="text-[#008A05] shrink-0"
              aria-hidden="true"
            />
            <div>
              <CardTitle className="text-sm font-bold text-[#222222]">
                Chính sách an toàn phiên
              </CardTitle>
              <CardDescription className="text-xs text-[#717171]">
                Tuân thủ tiêu chuẩn an toàn thông tin
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-2.5 text-xs text-[#717171] leading-relaxed">
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Hết hạn tự động:</strong> Phiên làm việc tự động
              hết hạn sau khoảng thời gian không hoạt động.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Thu hồi tức thì:</strong> Khi giấy phép truy cập bị
              thu hồi, mọi phiên đọc tài liệu liên quan bị ngắt lập tức.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
            <p>
              <strong className="text-[#222222]">Chống phát lại:</strong> Refresh token xoay vòng tự
              động để phát hiện sớm hành vi chiếm quyền điều khiển phiên.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
