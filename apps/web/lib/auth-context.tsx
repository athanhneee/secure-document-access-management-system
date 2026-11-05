'use client';

import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { apiClient, ApiError } from './api-client';

export interface AuthUser {
  id: string;
  username: string;
  fullName: string;
  email: string;
  departmentId: string | null;
  status: string;
  version: number;
  roles: string[];
  permissions: string[];
}

export type RoleType =
  'SYSTEM_ADMIN' | 'DOCUMENT_OWNER' | 'DOCUMENT_READER' | 'SECURITY_OFFICER' | 'AUDITOR';

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
 * Thuật toán: Máy Trạng Thái Phiên Xác Thực Không Chặn Điều Hướng & Suy Diễn Vai Trò Tức Thì (`AuthProvider`)
 * Mục đích: Duy trì trạng thái định danh người dùng trong bộ nhớ React mà không gọi lại `/users/me` mỗi khi chuyển tuyến đường Sidebar, giúp chuyển trang nội bộ phản hồi dưới `100ms`.
 * Cơ chế hoạt động:
 *   - `refreshUser`: Nạp `/users/me` đúng một lần khi khởi tạo phiên (hoặc khi gọi làm mới tường minh sau đăng nhập/MFA), xóa sạch trạng thái nếu gặp HTTP 401/403.
 *   - `activeRole`: Suy diễn đồng bộ trong bộ nhớ `O(1)` (`useMemo`) từ lựa chọn vai trò tức thời (`roleOverride`) và tiền tố `pathname` khớp bảng `ROLE_PATHS`, không phát sinh hiệu ứng phụ hay truy vấn mạng khi bấm chuyển trang.
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
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setUser(null);
        setRoleOverride(null);
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
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
      // Ignore errors on logout
    }
  }, [router]);

  const hasPermission = useCallback(
    (permission: string) => {
      if (!user) return false;
      return user.permissions.includes(permission);
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
