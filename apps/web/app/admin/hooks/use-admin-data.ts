'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  mapHealthReadyResponse,
  normalizeAbacPolicyRow,
  normalizeAttributeDefinitionRow,
} from '../helpers';
import type {
  AbacPolicyApiDto,
  AbacPolicyRow,
  AttributeDefinitionApiDto,
  AttributeDefinitionRow,
  DepartmentRow,
  HealthDashboardResponse,
  HealthReadyResponse,
  PermissionRow,
  RoleRow,
  SystemHealthData,
  UserRow,
  WatermarkConfigRow,
} from '../types';
import { useAdminMutations } from './use-admin-mutations';
import { useWatermarkSettings } from './use-watermark-settings';

/**
 * Thuật toán: Đồng bộ Song song Chịu lỗi Đa Phân hệ Quản trị (`useAdminData`)
 * Mục đích: Tải đồng thời các nguồn dữ liệu quản trị độc lập qua `Promise.allSettled` và xử lý trung thực phản hồi sức khỏe hạ tầng (bao gồm mã `503`).
 */
export function useAdminData() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const wm = useWatermarkSettings({
    onRefresh: async () => setRefreshTrigger((n) => n + 1),
    onSuccess: (msg) => {
      setErrorMessage(null);
      setMessage(msg);
    },
    onError: setErrorMessage,
  });
  const { hydrateConfigs } = wm;

  const refresh = useCallback(
    async (options?: { silent?: boolean }) => {
      if (!options?.silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);

      const [
        usersRes,
        deptsRes,
        rolesRes,
        permsRes,
        policiesRes,
        attrsRes,
        wmConfigsRes,
        healthRes,
        dashboardRes,
      ] = await Promise.allSettled([
        apiClient<{ data: UserRow[] }>('/users'),
        apiClient<{ data: DepartmentRow[] }>('/departments'),
        apiClient<{ data: RoleRow[] }>('/rbac/roles'),
        apiClient<{ data: PermissionRow[] }>('/rbac/permissions'),
        apiClient<{ data: AbacPolicyApiDto[] }>('/abac/policies'),
        apiClient<{ data: AttributeDefinitionApiDto[] }>('/abac/attributes'),
        apiClient<{ data: WatermarkConfigRow[] }>('/watermarks/configs'),
        apiClient<HealthReadyResponse>('/health/ready'),
        apiClient<HealthDashboardResponse>('/health/dashboard'),
      ]);

      if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data || []);
      if (deptsRes.status === 'fulfilled') setDepartments(deptsRes.value.data || []);
      if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value.data || []);
      if (permsRes.status === 'fulfilled') setPermissions(permsRes.value.data || []);
      if (policiesRes.status === 'fulfilled') {
        setPolicies((policiesRes.value.data || []).map(normalizeAbacPolicyRow));
      }
      if (attrsRes.status === 'fulfilled') {
        setAttributes((attrsRes.value.data || []).map(normalizeAttributeDefinitionRow));
      }
      if (wmConfigsRes.status === 'fulfilled') {
        hydrateConfigs(wmConfigsRes.value.data || []);
      }

      const dashboardData = dashboardRes.status === 'fulfilled' ? dashboardRes.value : null;
      if (healthRes.status === 'fulfilled') {
        setHealthData(mapHealthReadyResponse(healthRes.value, dashboardData));
      } else {
        const err = healthRes.reason;
        if (
          err instanceof ApiError &&
          err.response &&
          typeof err.response === 'object' &&
          ('checks' in err.response || 'status' in err.response)
        ) {
          setHealthData(
            mapHealthReadyResponse(err.response as unknown as HealthReadyResponse, dashboardData),
          );
        } else {
          setHealthData({
            status: 'OFFLINE',
            database: { status: 'OFFLINE' },
            cache: { status: 'OFFLINE' },
            uptimeSeconds: dashboardData?.process?.uptimeSeconds ?? 0,
          });
        }
      }

      if (!options?.silent) {
        setIsLoading(false);
      }
    },
    [hydrateConfigs],
  );

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refresh();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refresh, refreshTrigger]);

  const mutations = useAdminMutations({
    users,
    setUsers,
    roles,
    setRoles,
    policies,
    setPolicies,
    setMessage,
    setErrorMessage,
    refresh,
  });

  return {
    users,
    departments,
    roles,
    permissions,
    policies,
    attributes,
    healthData,
    watermark: wm,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    refresh,
    ...mutations,
  };
}
