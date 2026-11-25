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
  ClearanceOptionRow,
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
  const [clearanceOptions, setClearanceOptions] = useState<ClearanceOptionRow[]>([]);
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
        clearanceOptsRes,
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
        apiClient<{ data: ClearanceOptionRow[] }>('/users/clearance-options'),
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
      const normalizedAttrs =
        attrsRes.status === 'fulfilled'
          ? (attrsRes.value.data || []).map(normalizeAttributeDefinitionRow)
          : null;
      if (normalizedAttrs !== null) {
        setAttributes(normalizedAttrs);
      }
      if (clearanceOptsRes.status === 'fulfilled') {
        setClearanceOptions(clearanceOptsRes.value.data || []);
      } else if (normalizedAttrs !== null) {
        const clearanceDef = normalizedAttrs.find((a) => a.code === 'CLEARANCE_LEVEL');
        if (clearanceDef) {
          setClearanceOptions(
            clearanceDef.attribute_options
              .map((opt) => ({
                id: opt.id,
                code: opt.code,
                name: opt.name,
                rank: opt.numeric_rank ?? 0,
              }))
              .sort((a, b) => a.rank - b.rank),
          );
        }
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
            storage: { status: 'OFFLINE' },
            uptimeSeconds: dashboardData?.process?.uptimeSeconds ?? 0,
            ...(dashboardData?.process
              ? {
                  memory: {
                    heapUsedMb: dashboardData.process.heapUsedMb,
                    heapTotalMb: dashboardData.process.heapTotalMb,
                    rssMb: dashboardData.process.rssMb,
                  },
                }
              : {}),
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
    healthData,
    setMessage,
    setErrorMessage,
    refresh,
  });

  return {
    users,
    clearanceOptions,
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
