'use client';

import { Globe, Laptop, RefreshCw, ShieldCheck, Smartphone, Trash2 } from 'lucide-react';
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

export interface ActiveAuthSessionItem {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt?: string | null | undefined;
  expiresAt?: string | null | undefined;
  isCurrent: boolean;
}

interface ActiveSessionsListProps {
  sessions: ActiveAuthSessionItem[];
  isFetching: boolean;
  revokingId: string | null;
  onRefresh: () => void;
  onRevokeSession: (session: ActiveAuthSessionItem) => void;
}

/**
 * Thuật toán: Phân Tích Chuỗi User-Agent Định Danh Thiết Bị Truy Cập (`summarizeUserAgent`)
 * Mục đích: Rút gọn chuỗi định danh trình duyệt thô thành nhãn hệ điều hành và trình duyệt dễ đọc cho người dùng kiểm tra thiết bị lạ.
 */
function summarizeUserAgent(ua: string | null): { label: string; isMobile: boolean } {
  if (!ua || !ua.trim()) {
    return { label: 'Thiết bị trình duyệt web', isMobile: false };
  }
  const normalized = ua.toLowerCase();
  const isMobile = /iphone|ipad|android|mobile/.test(normalized);
  const browser = normalized.includes('edg/')
    ? 'Microsoft Edge'
    : normalized.includes('chrome/')
      ? 'Google Chrome'
      : normalized.includes('firefox/')
        ? 'Mozilla Firefox'
        : normalized.includes('safari/')
          ? 'Apple Safari'
          : 'Trình duyệt Web';
  const os = normalized.includes('windows')
    ? 'Windows'
    : normalized.includes('mac os') || normalized.includes('macintosh')
      ? 'macOS'
      : normalized.includes('android')
        ? 'Android'
        : normalized.includes('iphone') || normalized.includes('ipad')
          ? 'iOS'
          : normalized.includes('linux')
            ? 'Linux'
            : 'Hệ điều hành chuẩn';

  return { label: `${browser} · ${os}`, isMobile };
}

function formatTimestamp(iso?: string | null): string {
  if (!iso) return '—';
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return '—';
  return parsed.toLocaleString('vi-VN');
}

export function ActiveSessionsList({
  sessions,
  isFetching,
  revokingId,
  onRefresh,
  onRevokeSession,
}: ActiveSessionsListProps) {
  return (
    <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
        <div>
          <CardTitle className="text-base font-bold text-[#222222]">
            Danh sách thiết bị &amp; phiên đang hoạt động ({sessions.length})
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Kiểm tra địa chỉ IP, thời điểm tương tác cuối và thu hồi riêng từng phiên từ xa mà không
            làm gián đoạn thiết bị hiện tại
          </CardDescription>
        </div>
        <InteractiveHoverButton
          type="button"
          variant="secondary"
          size="sm"
          isLoading={isFetching}
          disabled={isFetching}
          icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
          text="Làm mới danh sách"
          onClick={onRefresh}
        />
      </CardHeader>

      <CardContent className="space-y-3">
        {isFetching && sessions.length === 0 ? (
          <div className="py-6 text-center text-xs text-[#717171]">
            Đang tải danh sách thiết bị đăng nhập…
          </div>
        ) : sessions.length === 0 ? (
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 text-xs text-[#717171]">
            Hiện chỉ ghi nhận phiên làm việc trực tiếp trên thiết bị này.
          </div>
        ) : (
          sessions.map((session) => {
            const { label, isMobile } = summarizeUserAgent(session.userAgent);
            const isRevokingThis = revokingId === session.id;
            return (
              <div
                key={session.id}
                className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 text-xs"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-2.5">
                    {isMobile ? (
                      <Smartphone
                        size={20}
                        strokeWidth={1.75}
                        className={session.isCurrent ? 'text-[#008A05]' : 'text-[#222222]'}
                        aria-hidden="true"
                      />
                    ) : (
                      <Laptop
                        size={20}
                        strokeWidth={1.75}
                        className={session.isCurrent ? 'text-[#008A05]' : 'text-[#222222]'}
                        aria-hidden="true"
                      />
                    )}
                    <span className="font-bold text-sm text-[#222222]">{label}</span>
                    <Badge variant={session.isCurrent ? 'success' : 'info'}>
                      {session.isCurrent ? 'Thiết bị này' : 'Phiên từ xa'}
                    </Badge>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#717171]">
                    <span className="inline-flex items-center gap-1 font-medium text-[#222222]">
                      <Globe
                        size={16}
                        strokeWidth={1.75}
                        className="text-[#717171]"
                        aria-hidden="true"
                      />
                      <span>IP: {session.ipAddress || '—'}</span>
                    </span>
                    <span>Đăng nhập: {formatTimestamp(session.createdAt)}</span>
                    <span>
                      Hoạt động cuối: {formatTimestamp(session.lastSeenAt || session.createdAt)}
                    </span>
                  </div>
                </div>

                {!session.isCurrent && (
                  <div className="shrink-0">
                    <InteractiveHoverButton
                      type="button"
                      variant="danger"
                      size="sm"
                      isLoading={isRevokingThis}
                      disabled={Boolean(revokingId)}
                      icon={<Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                      text="Thu hồi"
                      onClick={() => onRevokeSession(session)}
                    />
                  </div>
                )}
              </div>
            );
          })
        )}
      </CardContent>
    </Card>
  );
}

interface SessionSecurityOverviewProps {
  fullName?: string | undefined;
  username?: string | undefined;
  onLogoutCurrent: () => void;
}

export function SessionSecurityOverview({
  fullName,
  username,
  onLogoutCurrent,
}: SessionSecurityOverviewProps) {
  return (
    <div className="grid gap-5 md:grid-cols-2">
      <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
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
            <div className="flex justify-between items-center">
              <span className="text-[#717171]">Người dùng:</span>
              <span className="font-semibold text-[#222222]">
                {fullName} ({username})
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[#717171]">Bảo mật Cookie:</span>
              <span className="font-bold text-[#008A05] text-xs">HttpOnly · SameSite=Strict</span>
            </div>
            <div className="flex justify-between items-center">
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
