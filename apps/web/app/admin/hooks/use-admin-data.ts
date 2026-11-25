'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  mapHealthReadyResponse,
  normalizeAbacPolicyRow,
  normalizeAttributeDefinitionRow,
} from '../helpers';
import type {
  AbacPolicyApiDto,
  AbacPolicyRow,
  AdminTab,
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

function buildOfflineHealthData(): SystemHealthData {
  return {
    status: 'OFFLINE',
    database: { status: 'OFFLINE' },
    cache: { status: 'OFFLINE' },
    storage: { status: 'OFFLINE' },
    uptimeSeconds: 0,
  };
}

/**
 * Thuật toán: Tải Lười Theo Tab Phân Hệ Quản Trị & Loại Bỏ Gọi Trùng `/health/ready` (`useAdminData`)
 * Mục đích:
 *   - Thay thế fan-out 10 API đồng loạt khi mở `/admin` bằng tải theo yêu cầu đúng tab đang hiển thị (`users` chỉ gọi 3 API lần đầu, mỗi tab khác 1–2 API).
 *   - Loại bỏ lời gọi trùng `/health/ready` vì `/health/dashboard` đã chứa đầy đủ `dependencies.checks` (`database`, `redis`, `storage`) và số liệu tiến trình.
 *   - Khử trùng lặp yêu cầu đồng thời (`inFlightTabsRef`) và chỉ làm mới đúng phạm vi tab được yêu cầu sau thao tác hộp thoại.
 */
export function useAdminData(activeTab: AdminTab) {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [clearanceOptions, setClearanceOptions] = useState<ClearanceOptionRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [loadedTabs, setLoadedTabs] = useState<Partial<Record<AdminTab, boolean>>>({});
  const loadedTabsRef = useRef<Set<AdminTab>>(new Set());
  const departmentsLoadedRef = useRef(false);
  const clearanceLoadedRef = useRef(false);
  const inFlightTabsRef = useRef<Map<AdminTab, Promise<void>>>(new Map());

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const wm = useWatermarkSettings({
    onSuccess: (msg) => {
      setErrorMessage(null);
      setMessage(msg);
    },
    onError: setErrorMessage,
  });
  const { hydrateConfigs } = wm;

  const markTabLoaded = useCallback((tab: AdminTab) => {
    if (!loadedTabsRef.current.has(tab)) {
      loadedTabsRef.current.add(tab);
      setLoadedTabs((prev) => (prev[tab] ? prev : { ...prev, [tab]: true }));
    }
  }, []);

  const loadTab = useCallback(
    async (tab: AdminTab, options?: { silent?: boolean; force?: boolean }) => {
      if (!options?.force && loadedTabsRef.current.has(tab)) {
        return;
      }

      const existingInFlight = inFlightTabsRef.current.get(tab);
      if (existingInFlight && !options?.force) {
        await existingInFlight;
        return;
      }

      if (!options?.silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);

      const task = (async () => {
        if (tab === 'users') {
          const needDepartments =
            !departmentsLoadedRef.current || (!options?.silent && options?.force);
          const needClearance = !clearanceLoadedRef.current || (!options?.silent && options?.force);

          const [usersRes, deptsRes, clearanceOptsRes] = await Promise.allSettled([
            apiClient<{ data: UserRow[] }>('/users'),
            needDepartments
              ? apiClient<{ data: DepartmentRow[] }>('/departments')
              : Promise.resolve(null),
            needClearance
              ? apiClient<{ data: ClearanceOptionRow[] }>('/users/clearance-options')
              : Promise.resolve(null),
          ]);

          if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data || []);
          if (deptsRes.status === 'fulfilled' && deptsRes.value) {
            setDepartments(deptsRes.value.data || []);
            departmentsLoadedRef.current = true;
            markTabLoaded('departments');
          }
          if (clearanceOptsRes.status === 'fulfilled' && clearanceOptsRes.value) {
            setClearanceOptions(clearanceOptsRes.value.data || []);
            clearanceLoadedRef.current = true;
          }
          markTabLoaded('users');
          return;
        }

        if (tab === 'departments') {
          const [deptsRes] = await Promise.allSettled([
            apiClient<{ data: DepartmentRow[] }>('/departments'),
          ]);
          if (deptsRes.status === 'fulfilled') {
            setDepartments(deptsRes.value.data || []);
            departmentsLoadedRef.current = true;
          }
          markTabLoaded('departments');
          return;
        }

        if (tab === 'rbac') {
          const [rolesRes, permsRes] = await Promise.allSettled([
            apiClient<{ data: RoleRow[] }>('/rbac/roles'),
            apiClient<{ data: PermissionRow[] }>('/rbac/permissions'),
          ]);
          if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value.data || []);
          if (permsRes.status === 'fulfilled') setPermissions(permsRes.value.data || []);
          markTabLoaded('rbac');
          return;
        }

        if (tab === 'abac') {
          const [policiesRes, attrsRes] = await Promise.allSettled([
            apiClient<{ data: AbacPolicyApiDto[] }>('/abac/policies'),
            apiClient<{ data: AttributeDefinitionApiDto[] }>('/abac/attributes'),
          ]);
          if (policiesRes.status === 'fulfilled') {
            setPolicies((policiesRes.value.data || []).map(normalizeAbacPolicyRow));
          }
          if (attrsRes.status === 'fulfilled') {
            const normalizedAttrs = (attrsRes.value.data || []).map(
              normalizeAttributeDefinitionRow,
            );
            setAttributes(normalizedAttrs);
            if (!clearanceLoadedRef.current) {
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
                clearanceLoadedRef.current = true;
              }
            }
          }
          markTabLoaded('abac');
          return;
        }

        if (tab === 'watermark') {
          const [wmConfigsRes] = await Promise.allSettled([
            apiClient<{ data: WatermarkConfigRow[] }>('/watermarks/configs'),
          ]);
          if (wmConfigsRes.status === 'fulfilled') {
            hydrateConfigs(wmConfigsRes.value.data || []);
          }
          markTabLoaded('watermark');
          return;
        }

        if (tab === 'health') {
          try {
            const dashboardData = await apiClient<HealthDashboardResponse>('/health/dashboard');
            setHealthData(mapHealthReadyResponse(null, dashboardData));
          } catch (err) {
            if (err instanceof ApiError && err.response && typeof err.response === 'object') {
              const raw = err.response as Record<string, unknown>;
              if ('dependencies' in raw || 'process' in raw) {
                setHealthData(
                  mapHealthReadyResponse(null, raw as unknown as HealthDashboardResponse),
                );
              } else if ('checks' in raw || 'status' in raw) {
                setHealthData(mapHealthReadyResponse(raw as unknown as HealthReadyResponse, null));
              } else {
                setHealthData(buildOfflineHealthData());
              }
            } else {
              setHealthData(buildOfflineHealthData());
            }
          }
          markTabLoaded('health');
        }
      })();

      inFlightTabsRef.current.set(tab, task);
      try {
        await task;
      } finally {
        if (inFlightTabsRef.current.get(tab) === task) {
          inFlightTabsRef.current.delete(tab);
        }
        if (!options?.silent) {
          setIsLoading(false);
        }
      }
    },
    [hydrateConfigs, markTabLoaded],
  );

  const ensureTabLoaded = useCallback(
    (tab: AdminTab) => loadTab(tab, { silent: true, force: false }),
    [loadTab],
  );

  const refresh = useCallback(
    (options?: { silent?: boolean; tab?: AdminTab }) =>
      loadTab(options?.tab ?? activeTab, {
        ...(options?.silent !== undefined ? { silent: options.silent } : {}),
        force: true,
      }),
    [activeTab, loadTab],
  );

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        if (loadedTabsRef.current.has(activeTab)) {
          setIsLoading(false);
        } else {
          void loadTab(activeTab, { silent: false, force: false });
        }
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [activeTab, loadTab]);

  const mutations = useAdminMutations({
    setUsers,
    setRoles,
    policies,
    setPolicies,
    healthData,
    setMessage,
    setErrorMessage,
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
    loadedTabs,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    ensureTabLoaded,
    refresh,
    ...mutations,
  };
}
