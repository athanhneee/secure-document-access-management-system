'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  BusinessCategoryOptionRow,
  ClearanceOptionRow,
  DepartmentLookupRow,
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
export interface AdminTabPermissions {
  canManageDepartments?: boolean;
  canManageRoles?: boolean;
  canManagePolicies: boolean;
  canManageAttributes: boolean;
  canSimulatePolicy: boolean;
}

export function useAdminData(
  activeTab: AdminTab,
  tabPerms: AdminTabPermissions = {
    canManageDepartments: true,
    canManageRoles: true,
    canManagePolicies: true,
    canManageAttributes: true,
    canSimulatePolicy: true,
  },
) {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [clearanceOptions, setClearanceOptions] = useState<ClearanceOptionRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [departmentLookup, setDepartmentLookup] = useState<DepartmentLookupRow[]>([]);
  const [businessCategories, setBusinessCategories] = useState<BusinessCategoryOptionRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [loadedTabs, setLoadedTabs] = useState<Partial<Record<AdminTab, boolean>>>({});
  const loadedTabsRef = useRef<Set<AdminTab>>(new Set());
  const departmentsLoadedRef = useRef(false);
  const categoriesLoadedRef = useRef(false);
  const clearanceLoadedRef = useRef(false);
  const inFlightTabsRef = useRef<Map<AdminTab, Promise<void>>>(new Map());
  const {
    canManageDepartments = true,
    canManageRoles = true,
    canManagePolicies,
    canManageAttributes,
    canSimulatePolicy,
  } = tabPerms;

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
              ? canManageDepartments
                ? apiClient<{ data: DepartmentRow[] }>('/departments')
                : apiClient<{ data: DepartmentLookupRow[] }>('/departments/lookup')
              : Promise.resolve(null),
            needClearance
              ? apiClient<{ data: ClearanceOptionRow[] }>('/users/clearance-options')
              : Promise.resolve(null),
          ]);

          if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data || []);
          if (deptsRes.status === 'fulfilled' && deptsRes.value) {
            if (canManageDepartments) {
              setDepartments((deptsRes.value.data as DepartmentRow[]) || []);
              markTabLoaded('departments');
            } else {
              const lookupRows = (deptsRes.value.data as DepartmentLookupRow[]) || [];
              setDepartmentLookup(lookupRows);
              setDepartments(
                lookupRows.map((d) => ({
                  id: String(d.id),
                  code: d.code,
                  name: d.name,
                  parentId: null,
                  isActive: true,
                  version: 0,
                })),
              );
            }
            departmentsLoadedRef.current = true;
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
          if (!canManageRoles) {
            const [lookupRes] = await Promise.allSettled([
              apiClient<{
                data: Array<{
                  id: string;
                  code: string;
                  name: string;
                  description?: string | null;
                }>;
              }>('/rbac/roles/lookup'),
            ]);
            if (lookupRes.status === 'fulfilled') {
              setRoles(
                (lookupRes.value.data || []).map((r) => ({
                  id: String(r.id),
                  code: r.code,
                  name: r.name,
                  description: r.description ?? null,
                  isSystemRole: false,
                  isActive: true,
                  version: 0,
                  permissions: [],
                })),
              );
            }
            markTabLoaded('rbac');
            return;
          }
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
          const needDeptLookup = !departmentsLoadedRef.current || Boolean(options?.force);
          const needCategories = !categoriesLoadedRef.current || Boolean(options?.force);
          const canReadCategories = canManagePolicies || canSimulatePolicy;

          const [policiesRes, attrsRes, deptLookupRes, categoriesRes] = await Promise.allSettled([
            canManagePolicies
              ? apiClient<{ data: AbacPolicyApiDto[] }>('/abac/policies')
              : Promise.resolve(null),
            canManageAttributes
              ? apiClient<{ data: AttributeDefinitionApiDto[] }>('/abac/attributes')
              : Promise.resolve(null),
            needDeptLookup
              ? apiClient<{ data: DepartmentLookupRow[] }>('/departments/lookup')
              : Promise.resolve(null),
            needCategories && canReadCategories
              ? apiClient<{ data: BusinessCategoryOptionRow[] }>('/classifications/categories')
              : Promise.resolve(null),
          ]);
          if (policiesRes.status === 'fulfilled' && policiesRes.value) {
            setPolicies((policiesRes.value.data || []).map(normalizeAbacPolicyRow));
          }
          if (deptLookupRes.status === 'fulfilled' && deptLookupRes.value) {
            setDepartmentLookup(deptLookupRes.value.data || []);
          }
          if (categoriesRes.status === 'fulfilled' && categoriesRes.value) {
            setBusinessCategories(categoriesRes.value.data || []);
            categoriesLoadedRef.current = true;
          }
          if (attrsRes.status === 'fulfilled' && attrsRes.value) {
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
    [
      canManageAttributes,
      canManageDepartments,
      canManagePolicies,
      canManageRoles,
      canSimulatePolicy,
      hydrateConfigs,
      markTabLoaded,
    ],
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

  const abacDepartments = useMemo<DepartmentLookupRow[]>(() => {
    if (departments.length > 0) {
      return departments
        .filter((d) => d.isActive)
        .map((d) => ({ id: String(d.id), code: d.code, name: d.name }));
    }
    return departmentLookup;
  }, [departments, departmentLookup]);

  const mutations = useAdminMutations({
    setUsers,
    setDepartments,
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
    abacDepartments,
    businessCategories,
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
