'use client';

import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import {
  apiClient,
  ApiError,
  getCsrfToken,
  isPreMfaApiError,
  sanitizeRedirectPath,
  subscribeSessionExpired,
} from './api-client';
import { disconnectRealtimeStream, subscribeRealtimeEvent } from './realtime-events';
import { clearNotificationMemoryCache } from '@/components/navigation/notification-bell-dialog';
import {
  canAccessPortal as evaluatePortalAccess,
  checkEffectivePermission,
  getAccessiblePortals,
  PORTAL_PATHS,
  resolveDefaultPortalForUser,
  type PermissionPrincipalLike,
  type SystemRoleType,
} from './role-permissions';

export interface AuthUser {
  id: string;
  username: string;
  fullName: string;
  email: string;
  departmentId: string | null;
  departmentName?: string | null;
  clearanceOptionId?: string | null;
  clearanceCode?: string | null;
  clearanceName?: string | null;
  clearanceRank?: number;
  mfaEnabled?: boolean;
  mfaVerified?: boolean;
  status: string;
  version: number;
  roles: string[];
  permissions: string[];
  globalPermissions?: string[] | undefined;
  hasGlobalUserManage?: boolean | undefined;
  userManageDepartmentIds?: string[] | undefined;
  hasGlobalDocumentUpload?: boolean | undefined;
  documentUploadDepartmentIds?: string[] | undefined;
}

export type RoleType = SystemRoleType;

export const ROLE_LABELS: Record<RoleType, string> = {
  SYSTEM_ADMIN: 'Quản trị viên hệ thống',
  DOCUMENT_OWNER: 'Chủ sở hữu tài liệu',
  DOCUMENT_READER: 'Người đọc tài liệu',
  SECURITY_OFFICER: 'Cán bộ an ninh thông tin',
  AUDITOR: 'Kiểm toán viên độc lập',
};

export const ROLE_PATHS: Record<RoleType, string> = PORTAL_PATHS;

/**
 * Thuật toán: Suy Diễn Cổng Làm Việc Mặc Định & Chống Bẫy Chuyển Hướng Chéo Phân Hệ Theo Quyền Thực Tế (`resolveDefaultPortalForRoles`, `resolveAuthorizedRedirectPath`)
 * Mục đích:
 *   - Cho phép tài khoản vai trò tùy chỉnh (Custom Role như `HR_MANAGER` có `USER:MANAGE`) tự động vào đúng phân hệ được cấp quyền (`/admin`) thay vì bị đẩy nhầm vào `/reader` và nhận lỗi `403`.
 *   - Khi tài khoản bị gỡ sạch quyền (`permissions: []`), trả về `'/'` thay vì ép vào một phân hệ không còn quyền truy cập.
 */
export function resolveDefaultPortalForRoles(
  userOrRoles: PermissionPrincipalLike | readonly string[] | null | undefined,
): string {
  if (!userOrRoles) return '/';
  if (Array.isArray(userOrRoles)) {
    const fallbackOrder: readonly RoleType[] = [
      'SYSTEM_ADMIN',
      'DOCUMENT_OWNER',
      'SECURITY_OFFICER',
      'AUDITOR',
      'DOCUMENT_READER',
    ];
    for (const candidate of fallbackOrder) {
      if (userOrRoles.includes(candidate)) return ROLE_PATHS[candidate];
    }
    return '/';
  }
  return resolveDefaultPortalForUser(userOrRoles as PermissionPrincipalLike);
}

export function resolveAuthorizedRedirectPath(
  rawRedirect: string | null | undefined,
  userOrRoles: PermissionPrincipalLike | readonly string[] | null | undefined,
): string {
  const safeRedirect = sanitizeRedirectPath(rawRedirect, '/');
  const defaultPortal = resolveDefaultPortalForRoles(userOrRoles);

  if (!userOrRoles) {
    return safeRedirect;
  }
  if (safeRedirect === '/') {
    return defaultPortal;
  }

  const matchedPortal = (Object.entries(ROLE_PATHS) as Array<[RoleType, string]>).find(
    ([, portalPrefix]) =>
      safeRedirect === portalPrefix ||
      safeRedirect.startsWith(`${portalPrefix}/`) ||
      safeRedirect.startsWith(`${portalPrefix}?`),
  );

  if (matchedPortal) {
    const [portalKey] = matchedPortal;
    const isAllowed = Array.isArray(userOrRoles)
      ? userOrRoles.includes(portalKey)
      : evaluatePortalAccess(userOrRoles as PermissionPrincipalLike, portalKey);
    return isAllowed ? safeRedirect : defaultPortal;
  }

  return safeRedirect;
}

interface AuthContextValue {
  user: AuthUser | null;
  activeRole: RoleType | null;
  accessiblePortals: RoleType[];
  isLoading: boolean;
  isAuthenticated: boolean;
  mfaPending: boolean;
  setActiveRole: (role: RoleType) => void;
  hydrateUser: (nextUser: AuthUser | null) => void;
  refreshUser: () => Promise<AuthUser | null>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasGlobalPermission: (permission: string) => boolean;
  hasRole: (role: RoleType) => boolean;
  canAccessPortal: (portal: RoleType) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * Thuật toán: Máy Trạng Thái Phiên Xác Thực Không Chặn Điều Hướng, Định Tuyến Đúng Pre-MFA & Đăng Xuất Đợi Xóa Cookie (`AuthProvider`)
 * Mục đích:
 *   - Duy trì trạng thái định danh người dùng trong bộ nhớ React mà không gọi lại `/users/me` mỗi khi chuyển tuyến đường Sidebar.
 *   - Phân biệt lỗi `401` tiền-MFA (`mfa_required` -> `/mfa`, `V-14`, `BUG-036`) với lỗi hết phiên thực sự (`/login?reason=session_revoked`).
 *   - Khi đăng xuất (`logout`), đợi máy chủ xóa cookie HttpOnly (giới hạn 3 giây phòng rớt mạng) và xóa sạch cache thông báo trong RAM trước khi điều hướng (`V-11`).
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [mfaPending, setMfaPending] = useState(false);
  const [roleOverride, setRoleOverride] = useState<{
    role: RoleType;
    fromPath: string | null;
  } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const hydrateUser = useCallback((nextUser: AuthUser | null) => {
    setUser(nextUser);
    setMfaPending(false);
    if (!nextUser) {
      setRoleOverride(null);
    }
    setIsLoading(false);
  }, []);

  const refreshUser = useCallback(async (): Promise<AuthUser | null> => {
    try {
      const data = await apiClient<AuthUser>('/users/me');
      setMfaPending(false);
      setUser(data);
      return data;
    } catch (err) {
      // Chỉ xóa phiên khi 401 (hết hạn / chưa xác thực); tuyệt đối không tự ý đăng xuất khi gặp lỗi phân quyền hoặc lỗi mạng tạm thời
      if (err instanceof ApiError && err.status === 401) {
        setUser(null);
        setRoleOverride(null);
        setMfaPending(isPreMfaApiError(err));
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const forceExpireSession = useCallback(
    (reason: 'locked' | 'disabled' | 'session_revoked' | 'mfa_required') => {
      disconnectRealtimeStream();
      clearNotificationMemoryCache();
      setUser(null);
      setRoleOverride(null);
      if (reason === 'mfa_required') {
        setMfaPending(true);
        // BUG-036: Tuyệt đối giữ nguyên URL hiện tại khi đang đứng ở `/mfa...` (bảo toàn ?enroll=1&method=totp&redirect=...)
        if (!pathname?.startsWith('/mfa')) {
          const currentTarget =
            typeof window !== 'undefined'
              ? `${window.location.pathname}${window.location.search}`
              : pathname;
          if (
            currentTarget &&
            currentTarget !== '/' &&
            !currentTarget.startsWith('/login') &&
            !currentTarget.startsWith('/mfa')
          ) {
            router.replace(`/mfa?redirect=${encodeURIComponent(currentTarget)}`);
          } else {
            router.replace('/mfa');
          }
        }
        return;
      }
      setMfaPending(false);
      if (
        pathname === '/' ||
        pathname === '/forgot-password' ||
        pathname?.startsWith('/reset-password') ||
        pathname === '/login'
      ) {
        return;
      }
      router.replace(`/login?reason=${reason}`);
    },
    [pathname, router],
  );

  // BUG-036: Đăng ký kênh lắng nghe 401 ngay khi mount AuthProvider để không đánh rơi tín hiệu mfa_required lúc F5 khởi tải.
  useEffect(() => {
    return subscribeSessionExpired((reason) => {
      forceExpireSession(reason === 'mfa_required' ? 'mfa_required' : 'session_revoked');
    });
  }, [forceExpireSession]);

  useEffect(() => {
    if (!getCsrfToken()) {
      // oxlint-disable-next-line react/set-state-in-effect
      setIsLoading(false);
      return;
    }
    void refreshUser();
  }, [refreshUser]);

  /**
   * Thuật toán: Cưỡng Chế Đăng Xuất Tức Thì Khi Tài Khoản Bị Khóa/Vô Hiệu Qua SSE `USER_SESSION_REVOKED` (`AuthProvider`)
   */
  const authenticatedUserId = user?.id ?? null;
  useEffect(() => {
    if (!authenticatedUserId) {
      return;
    }
    const unsubscribeSse = subscribeRealtimeEvent<{
      userId?: string;
      status?: string;
      reason?: string;
    }>('USER_SESSION_REVOKED', (event) => {
      const targetUserId = event.payload?.userId;
      if (targetUserId && targetUserId !== authenticatedUserId) {
        return;
      }
      const status = String(event.payload?.status ?? '').toUpperCase();
      if (status === 'DISABLED') {
        forceExpireSession('disabled');
      } else if (status === 'LOCKED') {
        forceExpireSession('locked');
      } else {
        forceExpireSession('session_revoked');
      }
    });
    return () => {
      unsubscribeSse();
    };
  }, [authenticatedUserId, forceExpireSession]);

  const accessiblePortals = useMemo<RoleType[]>(() => getAccessiblePortals(user), [user]);

  const activeRole = useMemo<RoleType | null>(() => {
    if (!user || accessiblePortals.length === 0) {
      return null;
    }
    if (
      roleOverride &&
      roleOverride.fromPath === pathname &&
      accessiblePortals.includes(roleOverride.role)
    ) {
      return roleOverride.role;
    }
    const pathRole = Object.entries(ROLE_PATHS).find(([, path]) =>
      pathname?.startsWith(path),
    )?.[0] as RoleType | undefined;
    if (pathRole && accessiblePortals.includes(pathRole)) {
      return pathRole;
    }
    if (roleOverride && accessiblePortals.includes(roleOverride.role)) {
      return roleOverride.role;
    }
    return accessiblePortals[0] ?? null;
  }, [user, accessiblePortals, pathname, roleOverride]);

  const setActiveRole = useCallback(
    (role: RoleType) => {
      setRoleOverride({ role, fromPath: pathname });
    },
    [pathname],
  );

  const logout = useCallback(async () => {
    disconnectRealtimeStream();
    clearNotificationMemoryCache();
    try {
      await Promise.race([
        apiClient('/auth/logout', { method: 'POST' }),
        new Promise<void>((resolve) => setTimeout(resolve, 3000)),
      ]);
    } catch {
      // Đảm bảo vẫn dọn sạch trạng thái phiên phía client nếu mất mạng
    } finally {
      setUser(null);
      setMfaPending(false);
      setRoleOverride(null);
      router.replace('/login');
    }
  }, [router]);

  const hasPermission = useCallback(
    (permission: string) => checkEffectivePermission(user, permission),
    [user],
  );

  const hasGlobalPermission = useCallback(
    (permission: string) => {
      if (!user) return false;
      if (Array.isArray(user.globalPermissions)) {
        return checkEffectivePermission(
          { roles: user.roles, permissions: user.globalPermissions },
          permission,
        );
      }
      return checkEffectivePermission(user, permission);
    },
    [user],
  );

  const hasRole = useCallback(
    (role: RoleType) => {
      if (!user) return false;
      return user.roles.includes(role);
    },
    [user],
  );

  const canAccessPortal = useCallback(
    (portal: RoleType) => evaluatePortalAccess(user, portal),
    [user],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      activeRole,
      accessiblePortals,
      isLoading,
      isAuthenticated: Boolean(user),
      mfaPending,
      setActiveRole,
      hydrateUser,
      refreshUser,
      logout,
      hasPermission,
      hasGlobalPermission,
      hasRole,
      canAccessPortal,
    }),
    [
      user,
      activeRole,
      accessiblePortals,
      isLoading,
      mfaPending,
      setActiveRole,
      hydrateUser,
      refreshUser,
      logout,
      hasPermission,
      hasGlobalPermission,
      hasRole,
      canAccessPortal,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
