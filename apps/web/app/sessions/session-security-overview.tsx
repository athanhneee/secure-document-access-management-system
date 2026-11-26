'use client';

/**
 * Thuật toán: Tổng Quan Phiên Hiện Tại & Kiểm Chứng Giao Thức TLS Thực Tế (`SessionSecurityOverview`, V-25, V-30)
 * Mục đích:
 *   - Trình bày trung thực giao thức kết nối thực tế (`window.location.protocol === 'https:'`) thay vì cứng chữ `"Đã mã hóa"` khi chạy qua HTTP cục bộ (`V-25`).
 *   - Hiển thị đầy đủ danh tính, phòng ban và cấp thẩm quyền bảo mật của tài khoản hiện hành (`V-30`).
 */
import { useState, useSyncExternalStore } from 'react';
import { ChevronRight, Laptop, ShieldCheck } from 'lucide-react';
import { formatSafeDateVi } from '@/lib/ui-labels';
import { cn } from '@/lib/utils';
import { ClassificationBadge } from '@/components/classification-badge';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { HandwritingText } from '@/components/ui/handwriting-text';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const SESSION_SECURITY_POLICIES = [
  {
    id: 'auto-expire',
    title: 'Hết hạn tự động',
    detail: 'Khóa phiên khi không hoạt động vượt ngưỡng cho phép.',
  },
  {
    id: 'instant-revoke',
    title: 'Thu hồi tức thì',
    detail: 'Ngắt mọi phiên đọc tài liệu ngay khi quyền truy cập bị thu hồi.',
  },
  {
    id: 'anti-hijack',
    title: 'Chống chiếm đoạt phiên',
    detail: 'Tự động làm mới mã xác thực định kỳ để phát hiện và ngăn chặn truy cập trái phép.',
  },
] as const;

export interface SessionSecurityOverviewProps {
  fullName?: string | undefined;
  username?: string | undefined;
  departmentName?: string | null | undefined;
  clearanceCode?: string | null | undefined;
  clearanceRank?: number | undefined;
  mfaVerified?: boolean | undefined;
  ipAddress?: string | null | undefined;
  createdAt?: string | null | undefined;
  onLogoutCurrent: () => void;
}

export function SessionSecurityOverview({
  fullName,
  username,
  departmentName,
  clearanceCode,
  clearanceRank,
  mfaVerified,
  ipAddress,
  createdAt,
  onLogoutCurrent,
}: SessionSecurityOverviewProps) {
  const isHttps = useSyncExternalStore<boolean | null>(
    () => () => undefined,
    () => window.location.protocol === 'https:',
    () => null,
  );
  const [policyState, setPolicyState] = useState<
    Record<string, { open: boolean; revealKey: number }>
  >({});

  function togglePolicy(id: string) {
    setPolicyState((prev) => {
      const current = prev[id];
      const nextOpen = !current?.open;
      return {
        ...prev,
        [id]: {
          open: nextOpen,
          revealKey: nextOpen ? (current?.revealKey ?? 0) + 1 : (current?.revealKey ?? 0),
        },
      };
    });
  }

  const transportLabel =
    isHttps === null
      ? 'Đang kiểm tra kết nối…'
      : isHttps
        ? ipAddress
          ? `HTTPS (TLS) · IP ${ipAddress}`
          : 'Kết nối HTTPS (TLS)'
        : ipAddress
          ? `HTTP nội bộ (chưa bật TLS) · IP ${ipAddress}`
          : 'HTTP nội bộ (chưa bật TLS)';

  return (
    <div className="grid gap-4 lg:grid-cols-2 items-start">
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
            <Badge variant="success">Đang hoạt động</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-2.5 text-xs text-[#222222]">
          <div className="flex flex-wrap justify-between items-center gap-2">
            <span className="text-[#717171]">Người dùng</span>
            <span className="font-semibold text-[#222222]">
              {fullName} ({username})
            </span>
          </div>
          {departmentName && (
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Đơn vị trực thuộc</span>
              <span className="font-medium text-[#222222]">{departmentName}</span>
            </div>
          )}
          {clearanceCode && (
            <div className="flex flex-wrap justify-between items-center gap-2">
              <span className="text-[#717171]">Cấp thẩm quyền</span>
              <ClassificationBadge
                code={clearanceCode}
                rank={clearanceRank}
                showRank
                subject="user"
                size="sm"
              />
            </div>
          )}
          <div className="flex flex-wrap justify-between items-center gap-2">
            <span className="text-[#717171]">Xác thực đa yếu tố</span>
            <Badge variant={mfaVerified ? 'success' : 'warning'}>
              {mfaVerified ? 'Đã xác thực MFA' : 'Chưa xác thực MFA'}
            </Badge>
          </div>
          <div className="flex flex-wrap justify-between items-center gap-2">
            <span className="text-[#717171]">Thời điểm đăng nhập</span>
            <span className="font-medium text-[#222222]">
              {formatSafeDateVi(createdAt, { includeTime: true })}
            </span>
          </div>
          <div className="flex flex-wrap justify-between items-center gap-2">
            <span className="text-[#717171]">Kênh truyền tải</span>
            <span
              className={`font-medium ${isHttps ? 'text-[#008A05]' : isHttps === false ? 'text-[#C13515]' : 'text-[#717171]'}`}
            >
              {transportLabel}
            </span>
          </div>
        </CardContent>
        <CardFooter className="flex justify-end">
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
        <CardContent className="text-xs text-[#717171] leading-relaxed">
          <div className="divide-y divide-[#ebebeb]">
            {SESSION_SECURITY_POLICIES.map((policy) => {
              const itemState = policyState[policy.id];
              const isOpen = Boolean(itemState?.open);
              const revealKey = itemState?.revealKey ?? 0;
              return (
                <div key={policy.id} className="py-1 first:pt-0 last:pb-0">
                  <button
                    type="button"
                    onClick={() => togglePolicy(policy.id)}
                    aria-expanded={isOpen}
                    aria-controls={`session-policy-${policy.id}`}
                    className="group w-full min-h-11 sm:min-h-10 flex items-center justify-between gap-2 py-1.5 text-left cursor-pointer rounded-[12px] transition-colors hover:text-[#222222]"
                  >
                    <span className="flex items-center gap-2 min-w-0">
                      <span className="dot dot-success shrink-0" aria-hidden="true" />
                      <strong className="font-semibold text-[#222222]">{policy.title}</strong>
                    </span>
                    <span
                      className={cn(
                        'inline-flex h-6 w-6 items-center justify-center rounded-full text-[#717171] transition-colors group-hover:bg-[#f7f7f7] group-hover:text-[#222222] shrink-0',
                        isOpen && 'bg-[#f7f7f7] text-[#222222]',
                      )}
                      aria-hidden="true"
                    >
                      <ChevronRight
                        size={16}
                        strokeWidth={2}
                        className={cn(
                          'transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]',
                          isOpen && 'rotate-90',
                        )}
                      />
                    </span>
                  </button>

                  <div
                    id={`session-policy-${policy.id}`}
                    aria-hidden={!isOpen}
                    className={cn(
                      'grid transition-[grid-template-rows,opacity] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]',
                      isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
                    )}
                  >
                    <div className="overflow-hidden">
                      <p className="pl-3.5 pb-2 pt-0.5 text-xs text-[#717171] leading-relaxed">
                        <HandwritingText
                          key={`${policy.id}-${revealKey}`}
                          text={policy.detail}
                          active={isOpen}
                          startDelayMs={70}
                          charIntervalMs={20}
                          maxDurationMs={1150}
                        />
                      </p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
