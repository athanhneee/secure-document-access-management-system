'use client';

/**
 * Thuật toán: Không Gian Quản Lý Phiên Thiết Bị, Tự Phục Vụ MFA/Passkey & Đổi Mật Khẩu Có Xác Nhận WCAG (`SessionsPage`)
 * Mục đích: Bọc toàn trang trong `DialogErrorProvider`, quản lý phiên thiết bị kèm `ConfirmDialog`, kết nối trung tâm tự phục vụ MFA (`MfaFactorsCard`), Passkey (`PasskeyEnrollmentCard`) và đổi mật khẩu (`ChangePasswordCard`, `V-09`, `V-48`).
 */
import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { apiClient, ApiError } from '@/lib/api-client';
import { removeOptimisticById } from '@/lib/optimistic-state';
import { disconnectRealtimeStream } from '@/lib/realtime-events';
import { clearNotificationMemoryCache } from '@/components/navigation/notification-bell-dialog';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  ActiveSessionsList,
  SessionSecurityOverview,
  summarizeUserAgent,
  type ActiveAuthSessionItem,
} from './active-sessions-list';
import { ChangePasswordCard } from './change-password-card';
import { MfaFactorsCard } from './mfa-factors-card';
import { PasskeyEnrollmentCard } from './passkey-enrollment-card';

export default function SessionsPage() {
  return (
    <AuthGuard>
      <AppLayout>
        <SessionsPageContent />
      </AppLayout>
    </AuthGuard>
  );
}

function SessionsPageContent() {
  const router = useRouter();
  const { user, logout, hydrateUser, refreshUser } = useAuth();
  const [sessions, setSessions] = useState<ActiveAuthSessionItem[]>([]);
  const [isFetching, setIsFetching] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isRevokingOthers, setIsRevokingOthers] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);
  const [confirmRevokeTarget, setConfirmRevokeTarget] = useState<ActiveAuthSessionItem | null>(
    null,
  );
  const [confirmLogoutOthersOpen, setConfirmLogoutOthersOpen] = useState(false);
  const [confirmLogoutCurrentOpen, setConfirmLogoutCurrentOpen] = useState(false);
  const [mfaRefreshTick, setMfaRefreshTick] = useState(0);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  /**
   * Thuật toán: Đồng Bộ Danh Sách Phiên Thiết Bị Không Nuốt Lỗi & Thu Hồi Chọn Lọc Lạc Quan Dưới 16ms
   * Mục đích: Phân tách rõ trạng thái lỗi mạng/500 (`fetchError`) khỏi trạng thái không có phiên từ xa,
   * giữ nguyên dữ liệu cũ khi làm mới thất bại và hoàn trả ảnh chụp `previousSessions` nếu thu hồi lỗi.
   */
  const loadActiveSessions = useCallback(async (options?: { silent?: boolean }) => {
    if (!options?.silent) {
      setIsFetching(true);
      setFetchError(null);
    }
    try {
      const res = await apiClient<{ data?: ActiveAuthSessionItem[] } | ActiveAuthSessionItem[]>(
        '/auth/sessions',
      );
      const list = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
      setSessions(list);
      setFetchError(null);
    } catch (err) {
      const message =
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể tải danh sách phiên thiết bị. Vui lòng kiểm tra kết nối mạng và thử lại.';
      setFetchError(message);
      if (!options?.silent) {
        setErrorMessage(message);
      }
    } finally {
      if (!options?.silent) {
        setIsFetching(false);
      }
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
    const previousSessions = sessions;
    setConfirmRevokeTarget(null);
    setRevokingSessionId(target.id);
    setErrorMessage(null);
    setSessions((prev) => removeOptimisticById(prev, target.id));
    setSuccessMessage(
      target.ipAddress
        ? `Đã thu hồi phiên đăng nhập (IP: ${target.ipAddress}) thành công.`
        : 'Đã thu hồi phiên đăng nhập trên thiết bị từ xa thành công.',
    );

    try {
      await apiClient(`/auth/sessions/${target.id}`, { method: 'DELETE' });
      void loadActiveSessions({ silent: true });
    } catch (err) {
      setSessions(previousSessions);
      setSuccessMessage(null);
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
    // CONFLICT-RESOLVED: Chuyển từ /auth/logout-all sang /auth/logout-others kết hợp ConfirmDialog chuẩn WCAG và thu hồi lạc quan dưới 16ms mà không hủy cookie phiên hiện tại.
    const previousSessions = sessions;
    const optimisticRevokedCount = sessions.filter((s) => !s.isCurrent).length;
    setIsRevokingOthers(true);
    setConfirmLogoutOthersOpen(false);
    setErrorMessage(null);
    setSessions((prev) => prev.filter((s) => s.isCurrent));
    setSuccessMessage(
      optimisticRevokedCount > 0
        ? `Đã đăng xuất thành công ${optimisticRevokedCount} phiên trên các thiết bị khác. Phiên hiện tại vẫn được giữ nguyên.`
        : 'Đã thu hồi toàn bộ các phiên đăng nhập trên thiết bị khác thành công.',
    );

    try {
      const res = await apiClient<{ revokedCount?: number }>('/auth/logout-others', {
        method: 'POST',
      });
      const count = typeof res?.revokedCount === 'number' ? res.revokedCount : null;
      if (count !== null) {
        setSuccessMessage(
          `Đã đăng xuất thành công ${count} phiên trên các thiết bị khác. Phiên hiện tại vẫn được giữ nguyên.`,
        );
      }
      void loadActiveSessions({ silent: true });
    } catch (err) {
      setSessions(previousSessions);
      setSuccessMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể đăng xuất các thiết bị khác.'
          : 'Đã xảy ra lỗi khi thu hồi các phiên làm việc khác.',
      );
    } finally {
      setIsRevokingOthers(false);
    }
  }

  async function handleSecurityResetRedirect() {
    disconnectRealtimeStream();
    clearNotificationMemoryCache();
    hydrateUser(null);
    router.replace('/login');
  }

  const otherSessionsCount = sessions.filter((s) => !s.isCurrent).length;
  const currentSession = sessions.find((s) => s.isCurrent);
  const revokeTargetSummary = confirmRevokeTarget
    ? summarizeUserAgent(confirmRevokeTarget.userAgent).label
    : '';

  return (
    <DialogErrorProvider errorMessage={errorMessage} onDismiss={() => setErrorMessage(null)}>
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222]">
              Quản lý phiên và thiết bị
            </h1>
          </div>

          <InteractiveHoverButton
            variant="destructive"
            size="sm"
            onClick={() => setConfirmLogoutOthersOpen(true)}
            disabled={isRevokingOthers || isFetching || otherSessionsCount === 0}
            isLoading={isRevokingOthers}
            text={
              otherSessionsCount > 0
                ? `Đăng xuất tất cả thiết bị khác (${otherSessionsCount})`
                : 'Đăng xuất tất cả thiết bị khác'
            }
            className="w-full sm:w-auto min-h-11 sm:min-h-0 shrink-0"
          />
        </div>

        {successMessage && (
          <Alert variant="success" className="rounded-[20px] text-xs">
            <CheckCircle2
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#008A05]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2">{successMessage}</AlertDescription>
          </Alert>
        )}

        {errorMessage && !(fetchError && sessions.length === 0) && (
          <Alert variant="destructive" className="rounded-[20px] text-xs">
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
          fetchError={fetchError}
          revokingId={revokingSessionId}
          onRefresh={() => void loadActiveSessions()}
          onRequestRevokeSession={(session) => setConfirmRevokeTarget(session)}
        />

        <SessionSecurityOverview
          fullName={user?.fullName}
          username={user?.username}
          departmentName={user?.departmentName}
          clearanceCode={user?.clearanceCode}
          clearanceRank={user?.clearanceRank}
          mfaVerified={currentSession?.mfaVerified ?? user?.mfaVerified}
          ipAddress={currentSession?.ipAddress}
          createdAt={currentSession?.createdAt}
          onLogoutCurrent={() => setConfirmLogoutCurrentOpen(true)}
        />

        <MfaFactorsCard
          mfaVerified={currentSession?.mfaVerified ?? user?.mfaVerified}
          refreshTrigger={mfaRefreshTick}
          onSuccess={(msg) => {
            setErrorMessage(null);
            setSuccessMessage(msg);
            void refreshUser();
          }}
          onError={(msg) => {
            setSuccessMessage(null);
            setErrorMessage(msg);
          }}
          onAllMfaDisabled={handleSecurityResetRedirect}
        />

        <PasskeyEnrollmentCard
          mfaVerified={currentSession?.mfaVerified ?? user?.mfaVerified}
          onRegistered={async (msg) => {
            setErrorMessage(null);
            setSuccessMessage(msg);
            setMfaRefreshTick((prev) => prev + 1);
            await refreshUser();
            await loadActiveSessions({ silent: true });
          }}
          onError={(msg) => {
            setSuccessMessage(null);
            setErrorMessage(msg);
          }}
        />

        <ChangePasswordCard
          onPasswordChanged={handleSecurityResetRedirect}
          onError={() => {
            setSuccessMessage(null);
            setErrorMessage(null);
          }}
        />

        <ConfirmDialog
          open={Boolean(confirmRevokeTarget)}
          onOpenChange={(open) => {
            if (!open) setConfirmRevokeTarget(null);
          }}
          title="Thu hồi phiên thiết bị từ xa"
          description={
            confirmRevokeTarget
              ? `Bạn có chắc chắn muốn ngắt ngay lập tức phiên trên "${revokeTargetSummary}" (IP: ${confirmRevokeTarget.ipAddress || 'không xác định'})? Thiết bị đó sẽ phải đăng nhập và xác thực lại.`
              : ''
          }
          confirmText="Thu hồi phiên này"
          cancelText="Giữ nguyên"
          variant="danger"
          isLoading={Boolean(confirmRevokeTarget && revokingSessionId === confirmRevokeTarget.id)}
          onConfirm={() => {
            if (confirmRevokeTarget) {
              void handleRevokeSingleSession(confirmRevokeTarget);
            }
          }}
        />

        <ConfirmDialog
          open={confirmLogoutOthersOpen}
          onOpenChange={setConfirmLogoutOthersOpen}
          title="Đăng xuất khỏi tất cả thiết bị khác"
          description="Bạn có chắc chắn muốn thu hồi ngay lập tức toàn bộ các phiên đăng nhập đang mở trên những thiết bị khác không? Phiên làm việc trên thiết bị hiện tại vẫn được giữ nguyên."
          confirmText="Đăng xuất thiết bị khác"
          cancelText="Giữ nguyên"
          variant="danger"
          isLoading={isRevokingOthers}
          onConfirm={handleLogoutOthers}
        />

        <ConfirmDialog
          open={confirmLogoutCurrentOpen}
          onOpenChange={setConfirmLogoutCurrentOpen}
          title="Đăng xuất khỏi thiết bị hiện tại"
          description="Bạn có chắc chắn muốn kết thúc phiên làm việc hiện tại trên thiết bị này không?"
          confirmText="Đăng xuất ngay"
          cancelText="Ở lại"
          variant="danger"
          onConfirm={() => {
            setConfirmLogoutCurrentOpen(false);
            void logout();
          }}
        />
      </div>
    </DialogErrorProvider>
  );
}
