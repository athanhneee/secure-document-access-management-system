'use client';

/**
 * Thuật toán: Hiển Thị Danh Sách Phiên Thiết Bị, Tách Biệt Trạng Thái Lỗi Tải & Thu Hồi Qua Xác Nhận (`ActiveSessionsList`)
 * Mục đích: Phân tích chính xác chuỗi User-Agent (iOS/iPadOS/Android/Desktop), hiển thị phẳng nhãn `mfaVerified`
 * theo mẫu `staff-001` trên nền trắng WCAG 2.1 AA, báo lỗi tường minh kèm nút tải lại khi API thất bại thay vì
 * nuốt lỗi thành trạng thái rỗng, và tối ưu vùng chạm `>= 44px` trên thiết bị di động `375px`.
 */
import { AlertTriangle, Globe, Laptop, RefreshCw, Smartphone, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatSessionTimestamp, summarizeUserAgent } from './session-device.helper';

export { SessionSecurityOverview } from './session-security-overview';
export { summarizeUserAgent, formatSessionTimestamp } from './session-device.helper';

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
  fetchError: string | null;
  revokingId: string | null;
  onRefresh: () => void;
  onRequestRevokeSession: (session: ActiveAuthSessionItem) => void;
}

export function ActiveSessionsList({
  sessions,
  isFetching,
  fetchError,
  revokingId,
  onRefresh,
  onRequestRevokeSession,
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
          className="w-full sm:w-auto min-h-11 sm:min-h-0 shrink-0"
        />
      </CardHeader>

      <CardContent className="space-y-2.5">
        {isFetching && sessions.length === 0 ? (
          <div className="py-6 text-center text-xs text-[#717171]">
            Đang tải danh sách thiết bị đăng nhập…
          </div>
        ) : fetchError && sessions.length === 0 ? (
          <div
            role="alert"
            className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[16px] border border-[#dddddd] bg-[#f7f7f7] p-3.5 text-xs text-[#C13515]"
          >
            <div className="flex items-start gap-2 min-w-0">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 mt-0.5 text-[#C13515]"
                aria-hidden="true"
              />
              <div className="space-y-0.5 min-w-0">
                <p className="font-semibold">Không thể tải danh sách phiên thiết bị</p>
                <p className="text-[#222222] leading-relaxed">{fetchError}</p>
              </div>
            </div>
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              isLoading={isFetching}
              disabled={isFetching}
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              text="Thử tải lại"
              onClick={onRefresh}
              className="w-full sm:w-auto min-h-11 sm:min-h-0 shrink-0"
            />
          </div>
        ) : sessions.length === 0 ? (
          <p className="text-xs text-[#717171] leading-relaxed">
            Hiện chưa ghi nhận phiên hoạt động nào khả dụng để hiển thị.
          </p>
        ) : (
          <div className="divide-y divide-[#ebebeb]">
            {sessions.map((session) => {
              const { label, isMobile } = summarizeUserAgent(session.userAgent);
              const isRevokingThis = revokingId === session.id;
              const isMfaVerified = Boolean(session.mfaVerified);
              return (
                <div
                  key={session.id}
                  className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-3 first:pt-1 last:pb-0 text-xs"
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
                      <span
                        className="font-bold text-sm text-[#222222]"
                        title={session.userAgent ?? undefined}
                      >
                        {label}
                      </span>
                      <Badge variant={session.isCurrent ? 'success' : 'info'}>
                        {session.isCurrent ? 'Thiết bị này' : 'Phiên từ xa'}
                      </Badge>
                      <Badge variant={isMfaVerified ? 'success' : 'warning'}>
                        {isMfaVerified ? 'Đã xác thực MFA' : 'Chưa xác thực MFA'}
                      </Badge>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#717171]">
                      <span className="inline-flex items-center gap-1 font-medium text-[#222222] min-w-0 break-all">
                        <Globe
                          size={16}
                          strokeWidth={1.75}
                          className="text-[#717171] shrink-0"
                          aria-hidden="true"
                        />
                        <span>IP: {session.ipAddress || '—'}</span>
                      </span>
                      <span>Đăng nhập: {formatSessionTimestamp(session.createdAt)}</span>
                      <span>
                        Hoạt động cuối:{' '}
                        {formatSessionTimestamp(session.lastSeenAt || session.createdAt)}
                      </span>
                      {session.expiresAt && (
                        <span>Hết hạn: {formatSessionTimestamp(session.expiresAt)}</span>
                      )}
                    </div>
                  </div>

                  {!session.isCurrent && (
                    <div className="shrink-0 w-full sm:w-auto">
                      <InteractiveHoverButton
                        type="button"
                        variant="danger"
                        size="sm"
                        isLoading={isRevokingThis}
                        disabled={Boolean(revokingId)}
                        icon={<Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                        text="Thu hồi"
                        onClick={() => onRequestRevokeSession(session)}
                        className="w-full sm:w-auto min-h-11 sm:min-h-0"
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
