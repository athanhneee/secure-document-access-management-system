'use client';

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { apiClient, ApiError } from '@/lib/api-client';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  ActiveSessionsList,
  SessionSecurityOverview,
  type ActiveAuthSessionItem,
} from './active-sessions-list';

export default function SessionsPage() {
  const { user, logout } = useAuth();
  const [sessions, setSessions] = useState<ActiveAuthSessionItem[]>([]);
  const [isFetching, setIsFetching] = useState(true);
  const [isRevokingOthers, setIsRevokingOthers] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);
  const [confirmLogoutOthersOpen, setConfirmLogoutOthersOpen] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  /**
   * Thuật toán: Đồng Bộ Danh Sách Phiên Thiết Bị Đang Mở & Thu Hồi Chọn Lọc Không Hủy Phiên Hiện Tại (`loadActiveSessions`, `handleRevokeSingleSession`, `handleLogoutOthers`)
   * Mục đích: Truy vấn `/auth/sessions` để liệt kê mọi phiên đăng nhập còn hiệu lực, cho phép thu hồi từng phiên qua `DELETE /auth/sessions/:id` hoặc thu hồi toàn bộ thiết bị khác qua `POST /auth/logout-others` mà vẫn bảo toàn cookie phiên hiện tại.
   */
  const loadActiveSessions = useCallback(async () => {
    setIsFetching(true);
    try {
      const res = await apiClient<{ data?: ActiveAuthSessionItem[] } | ActiveAuthSessionItem[]>(
        '/auth/sessions',
      );
      const list = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
      setSessions(list);
    } catch {
      setSessions([]);
    } finally {
      setIsFetching(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void loadActiveSessions();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [loadActiveSessions]);

  async function handleRevokeSingleSession(target: ActiveAuthSessionItem) {
    if (target.isCurrent) {
      return;
    }
    setRevokingSessionId(target.id);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      await apiClient(`/auth/sessions/${target.id}`, { method: 'DELETE' });
      setSuccessMessage(
        `Đã thu hồi phiên đăng nhập từ địa chỉ IP ${target.ipAddress || 'từ xa'} thành công.`,
      );
      await loadActiveSessions();
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể thu hồi phiên thiết bị này.'
          : 'Đã xảy ra lỗi khi thu hồi phiên thiết bị.',
      );
    } finally {
      setRevokingSessionId(null);
    }
  }

  async function handleLogoutOthers() {
    // CONFLICT-RESOLVED: Chuyển từ /auth/logout-all sang /auth/logout-others kết hợp ConfirmDialog chuẩn WCAG để thu hồi các thiết bị khác mà không hủy cookie phiên hiện tại.
    setIsRevokingOthers(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const res = await apiClient<{ revokedCount?: number }>('/auth/logout-others', {
        method: 'POST',
      });
      setConfirmLogoutOthersOpen(false);
      const count = typeof res?.revokedCount === 'number' ? res.revokedCount : null;
      setSuccessMessage(
        count !== null
          ? `Đã đăng xuất thành công ${count} phiên trên các thiết bị khác. Phiên hiện tại vẫn được giữ nguyên.`
          : 'Đã thu hồi toàn bộ các phiên đăng nhập trên thiết bị khác thành công.',
      );
      await loadActiveSessions();
    } catch (err) {
      setConfirmLogoutOthersOpen(false);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể đăng xuất các thiết bị khác.'
          : 'Đã xảy ra lỗi khi thu hồi các phiên làm việc khác.',
      );
    } finally {
      setIsRevokingOthers(false);
    }
  }

  const otherSessionsCount = sessions.filter((s) => !s.isCurrent).length;

  return (
    <AuthGuard>
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222]">
                Quản lý phiên làm việc & thiết bị
              </h1>
              <p className="text-xs text-[#717171] mt-1">
                Theo dõi các phiên đăng nhập đang hoạt động và thu hồi quyền truy cập khi có nghi
                ngờ rò rỉ
              </p>
            </div>

            <InteractiveHoverButton
              variant="destructive"
              onClick={() => setConfirmLogoutOthersOpen(true)}
              disabled={isRevokingOthers}
              isLoading={isRevokingOthers}
              text={
                otherSessionsCount > 0
                  ? `Đăng xuất tất cả thiết bị khác (${otherSessionsCount})`
                  : 'Đăng xuất tất cả thiết bị khác'
              }
              className="w-full sm:w-auto"
            />
          </div>

          {successMessage && (
            <Alert className="rounded-[20px] border border-[#008A05]/30 bg-[#008A05]/10 text-[#008A05] text-xs">
              <CheckCircle2
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#008A05]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{successMessage}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert
              variant="destructive"
              className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
            >
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#C13515]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          <ActiveSessionsList
            sessions={sessions}
            isFetching={isFetching}
            revokingId={revokingSessionId}
            onRefresh={() => void loadActiveSessions()}
            onRevokeSession={(session) => void handleRevokeSingleSession(session)}
          />

          <SessionSecurityOverview
            fullName={user?.fullName}
            username={user?.username}
            onLogoutCurrent={() => void logout()}
          />

          <ConfirmDialog
            open={confirmLogoutOthersOpen}
            onOpenChange={setConfirmLogoutOthersOpen}
            title="Đăng xuất khỏi tất cả thiết bị khác"
            description="Bạn có chắc chắn muốn thu hồi ngay lập tức toàn bộ các phiên đăng nhập đang mở trên những thiết bị khác không? Thiết bị hiện tại và cookie phiên này vẫn được giữ nguyên."
            confirmText="Đăng xuất thiết bị khác"
            cancelText="Giữ nguyên"
            variant="danger"
            isLoading={isRevokingOthers}
            onConfirm={handleLogoutOthers}
          />
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
