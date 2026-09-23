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

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [activeRole, setActiveRoleState] = useState<RoleType | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const refreshUser = useCallback(async (): Promise<AuthUser | null> => {
    try {
      const data = await apiClient<AuthUser>('/users/me');
      setUser(data);

      // Determine default active role
      if (data.roles && data.roles.length > 0) {
        // If current path matches a role, set that role as active
        const pathRole = Object.entries(ROLE_PATHS).find(([, path]) =>
          pathname?.startsWith(path),
        )?.[0] as RoleType | undefined;

        if (pathRole && data.roles.includes(pathRole)) {
          setActiveRoleState(pathRole);
        } else {
          setActiveRoleState((prev) =>
            prev && data.roles.includes(prev) ? prev : (data.roles[0] as RoleType),
          );
        }
      }
      return data;
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setUser(null);
        setActiveRoleState(null);
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, [pathname]);

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    void refreshUser();
  }, [refreshUser]);

  const setActiveRole = useCallback((role: RoleType) => {
    setActiveRoleState(role);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiClient('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore errors on logout
    } finally {
      setUser(null);
      setActiveRoleState(null);
      router.push('/login');
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
