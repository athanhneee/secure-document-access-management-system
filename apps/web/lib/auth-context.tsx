'use client';

import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { apiClient, ApiError, getCsrfToken, sanitizeRedirectPath } from './api-client';
import { checkEffectivePermission, type SystemRoleType } from './role-permissions';

export interface AuthUser {
  id: string;
  username: string;
  fullName: string;
  email: string;
  departmentId: string | null;
  clearanceOptionId?: string | null;
  clearanceCode?: string | null;
  clearanceName?: string | null;
  clearanceRank?: number;
  status: string;
  version: number;
  roles: string[];
  permissions: string[];
}

export type RoleType = SystemRoleType;

export const ROLE_LABELS: Record<RoleType, string> = {
  SYSTEM_ADMIN: 'Quản trị viên hệ thống',
  DOCUMENT_OWNER: 'Chủ sở hữu tài liệu',
  DOCUMENT_READER: 'Người đọc tài liệu',
  SECURITY_OFFICER: 'Cán bộ an ninh thông tin',
  AUDITOR: 'Kiểm toán viên',
};

export const ROLE_PATHS: Record<RoleType, string> = {
  SYSTEM_ADMIN: '/admin',
  DOCUMENT_OWNER: '/owner',
  DOCUMENT_READER: '/reader',
  SECURITY_OFFICER: '/security',
  AUDITOR: '/auditor',
};

const ROLE_PRIORITY_ORDER: readonly RoleType[] = [
  'SYSTEM_ADMIN',
  'DOCUMENT_OWNER',
  'SECURITY_OFFICER',
  'AUDITOR',
  'DOCUMENT_READER',
];

/**
 * Thuật toán: Suy Diễn Cổng Làm Việc Mặc Định & Chống Bẫy Chuyển Hướng Chéo Vai Trò (`resolveDefaultPortalForRoles`, `resolveAuthorizedRedirectPath`)
 * Mục đích:
 *   - Ngăn chặn tình huống người dùng đăng nhập qua liên kết `?redirect=/admin` (hoặc cổng vai trò khác) nhưng tài khoản thực tế thuộc vai trò khác (như `DOCUMENT_READER`) bị đẩy thẳng vào màn hình `403`.
 *   - Nếu đường dẫn `redirect` thuộc một trong 5 tiền tố cổng phân quyền mà tài khoản không sở hữu vai trò tương ứng, tự động chuyển về cổng mặc định đúng với vai trò của tài khoản.
 */
export function resolveDefaultPortalForRoles(roles: readonly string[] | undefined): string {
  if (!roles || roles.length === 0) return '/';
  for (const candidate of ROLE_PRIORITY_ORDER) {
    if (roles.includes(candidate)) {
      return ROLE_PATHS[candidate];
    }
  }
  return ROLE_PATHS.DOCUMENT_READER;
}

export function resolveAuthorizedRedirectPath(
  rawRedirect: string | null | undefined,
  roles: readonly string[] | undefined,
): string {
  const safeRedirect = sanitizeRedirectPath(rawRedirect, '/');
  const defaultPortal = resolveDefaultPortalForRoles(roles);

  if (!roles || roles.length === 0) {
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
    const [requiredRole] = matchedPortal;
    return roles.includes(requiredRole) ? safeRedirect : defaultPortal;
  }

  return safeRedirect;
}

interface AuthContextValue {
  user: AuthUser | null;
  activeRole: RoleType | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  setActiveRole: (role: RoleType) => void;
  refreshUser: () => Promise<AuthUser | null>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasRole: (role: RoleType) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * Thuật toán: Máy Trạng Thái Phiên Xác Thực Không Chặn Điều Hướng & Bỏ Qua Thăm Dò Khi Chưa Có Cookie (`AuthProvider`)
 * Mục đích:
 *   - Duy trì trạng thái định danh người dùng trong bộ nhớ React mà không gọi lại `/users/me` mỗi khi chuyển tuyến đường Sidebar, giúp chuyển trang nội bộ phản hồi dưới `100ms`.
 *   - Khi khởi tạo trên trình duyệt chưa có cookie `sda_csrf` (khách vãng lai trên trang công khai `/`), bỏ qua lời gọi `/api/v1/users/me` để loại bỏ hoàn toàn lỗi `401` đỏ trên Console.
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [roleOverride, setRoleOverride] = useState<{
    role: RoleType;
    fromPath: string | null;
  } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const refreshUser = useCallback(async (): Promise<AuthUser | null> => {
    try {
      const data = await apiClient<AuthUser>('/users/me');
      setUser(data);
      return data;
    } catch (err) {
      // Chỉ xóa phiên khi 401 (hết hạn / chưa xác thực); tuyệt đối không tự ý đăng xuất khi gặp 403 Forbidden hoặc lỗi mạng tạm thời
      if (err instanceof ApiError && err.status === 401) {
        setUser(null);
        setRoleOverride(null);
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!getCsrfToken()) {
      // oxlint-disable-next-line react/set-state-in-effect
      setIsLoading(false);
      return;
    }
    void refreshUser();
  }, [refreshUser]);

  const activeRole = useMemo<RoleType | null>(() => {
    if (!user || !user.roles || user.roles.length === 0) {
      return null;
    }
    if (
      roleOverride &&
      roleOverride.fromPath === pathname &&
      user.roles.includes(roleOverride.role)
    ) {
      return roleOverride.role;
    }
    const pathRole = Object.entries(ROLE_PATHS).find(([, path]) =>
      pathname?.startsWith(path),
    )?.[0] as RoleType | undefined;
    if (pathRole && user.roles.includes(pathRole)) {
      return pathRole;
    }
    if (roleOverride && user.roles.includes(roleOverride.role)) {
      return roleOverride.role;
    }
    return user.roles[0] as RoleType;
  }, [user, pathname, roleOverride]);

  const setActiveRole = useCallback(
    (role: RoleType) => {
      setRoleOverride({ role, fromPath: pathname });
    },
    [pathname],
  );

  const logout = useCallback(async () => {
    const logoutPromise = apiClient('/auth/logout', { method: 'POST' });
    setUser(null);
    setRoleOverride(null);
    router.push('/login');
    try {
      await logoutPromise;
    } catch {
      // Bỏ qua lỗi mạng khi đăng xuất vì trạng thái cục bộ đã được xóa sạch
    }
  }, [router]);

  const hasPermission = useCallback(
    (permission: string) => checkEffectivePermission(user, permission),
    [user],
  );

  const hasRole = useCallback(
    (role: RoleType) => {
      if (!user) return false;
      return user.roles.includes(role);
    },
    [user],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      activeRole,
      isLoading,
      isAuthenticated: Boolean(user),
      setActiveRole,
      refreshUser,
      logout,
      hasPermission,
      hasRole,
    }),
    [user, activeRole, isLoading, setActiveRole, refreshUser, logout, hasPermission, hasRole],
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
