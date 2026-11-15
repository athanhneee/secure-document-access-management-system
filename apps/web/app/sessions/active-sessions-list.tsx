'use client';

/**
 * Thuật toán: Phân Tích Chuỗi User-Agent & Biểu Diễn Phẳng Trạng Thái Xác Thực MFA Theo Phiên (`ActiveSessionsList`)
 * Mục đích: Rút gọn chuỗi trình duyệt/hệ điều hành, hiển thị rõ nhãn `mfaVerified` phẳng theo mẫu `staff-001` trên nền trắng đạt chuẩn tương phản WCAG 2.1 AA (`>= 4.5:1`) và cho phép thu hồi chọn lọc từng phiên từ xa.
 */
import { Globe, Laptop, RefreshCw, Smartphone, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export { SessionSecurityOverview } from './session-security-overview';

export interface ActiveAuthSessionItem {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt?: string | null | undefined;
  expiresAt?: string | null | undefined;
  isCurrent: boolean;
  mfaVerified?: boolean | undefined;
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
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
        <CardTitle className="text-sm sm:text-base font-bold text-[#222222]">
          Thiết bị đang đăng nhập ({sessions.length})
        </CardTitle>
        <InteractiveHoverButton
          type="button"
          variant="secondary"
          size="sm"
          isLoading={isFetching}
          disabled={isFetching}
          icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
          text="Làm mới"
          onClick={onRefresh}
          className="shrink-0"
        />
      </CardHeader>

      <CardContent className="space-y-2.5">
        {isFetching && sessions.length === 0 ? (
          <div className="py-6 text-center text-xs text-[#717171]">
            Đang tải danh sách thiết bị đăng nhập…
          </div>
        ) : sessions.length === 0 ? (
          <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 text-xs text-[#717171]">
            Hiện chỉ ghi nhận phiên làm việc trực tiếp trên thiết bị này.
          </div>
        ) : (
          sessions.map((session) => {
            const { label, isMobile } = summarizeUserAgent(session.userAgent);
            const isRevokingThis = revokingId === session.id;
            const isMfaVerified = Boolean(session.mfaVerified);
            return (
              <div
                key={session.id}
                className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3.5 text-xs"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
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
                    <Badge variant={isMfaVerified ? 'success' : 'warning'}>
                      {isMfaVerified ? 'Đã xác thực MFA' : 'Chưa xác thực MFA'}
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
