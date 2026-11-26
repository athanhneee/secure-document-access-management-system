'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  isGenuineHealthPayload,
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
import type { UserListQueryState } from '../users-query';
import { useAdminMutations } from './use-admin-mutations';
import { useWatermarkSettings } from './use-watermark-settings';

const ADMIN_USERS_PAGE_SIZE = 20;

interface UsersListResponse {
  data: UserRow[];
  total?: number;
  page?: number;
  pageSize?: number;
  totalPages?: number;
  truncated?: boolean;
}

function isAbortErr(err: unknown): boolean {
  return (
    (typeof DOMException !== 'undefined' &&
      err instanceof DOMException &&
      err.name === 'AbortError') ||
    (err instanceof Error && err.name === 'AbortError')
  );
}

function buildUsersEndpoint(query: UserListQueryState | undefined, page: number): string {
  const params = new URLSearchParams({
    page: String(Math.max(1, page)),
    pageSize: String(ADMIN_USERS_PAGE_SIZE),
  });
  if (query) {
    const trimmedSearch = query.searchQuery.trim();
    if (trimmedSearch) {
      params.set('search', trimmedSearch.slice(0, 120));
    }
    if (query.statusFilter !== 'ALL') {
      params.set('status', query.statusFilter);
    } else if (query.actionFilter === 'LOCK') {
      params.set('status', 'ACTIVE');
    } else if (query.actionFilter === 'UNLOCK') {
      params.set('status', 'LOCKED');
    }
    if (query.departmentFilter !== 'ALL') {
      params.set('departmentId', query.departmentFilter);
    }
  }
  return `/users?${params.toString()}`;
}

/**
 * Thuật toán: Trích Xuất Thông Điệp Lỗi Đã Việt Hóa Từ Kết Quả `PromiseSettledResult` Bị Từ Chối (`extractFirstRejectedError`)
 */
function extractFirstRejectedError(
  results: readonly PromiseSettledResult<unknown>[],
  fallbackMessage: string,
): string | null {
  for (const res of results) {
    if (res.status === 'rejected') {
      const reason = res.reason;
      if (reason instanceof ApiError && reason.message) {
        return reason.message;
      }
      return fallbackMessage;
    }
  }
  return null;
}

/**
 * Thuật toán: Tải Lười Theo Tab Phân Hệ Quản Trị Có Kiểm Định Thành Công Toàn Phần & Cổng An Toàn Quyền RBAC (`useAdminData`, BUG-091, BUG-092, BUG-098)
 * Mục đích:
 *   - Chỉ đánh dấu `markTabLoaded(tab)` khi toàn bộ API bắt buộc của tab hoàn tất `'fulfilled'`, cho phép thử lại ngay khi mạng gián đoạn.
 *   - Theo dõi cờ an toàn `permissionsLoaded` độc lập để chặn triệt để nguy cơ gửi `{ permissionIds: [] }` xóa trắng quyền vai trò khi `GET /rbac/permissions` lỗi.
 *   - Phân biệt phản hồi `503` suy giảm thực sự với lỗi đứt kết nối trình duyệt trên `SystemHealthTab`, và không gọi `/departments/lookup` khi tài khoản chỉ có `ATTRIBUTE:MANAGE`.
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
  userQuery?: UserListQueryState,
) {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [usersPage, setUsersPageState] = useState(1);
  const [usersTotalPages, setUsersTotalPages] = useState(1);
  const [usersTotal, setUsersTotal] = useState<number | null>(null);
  const [usersTruncated, setUsersTruncated] = useState(false);
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);
  const [debouncedUserSearch, setDebouncedUserSearch] = useState(userQuery?.searchQuery ?? '');
  const usersAbortRef = useRef<AbortController | null>(null);
  const usersSeqRef = useRef(0);
  const usersPageRef = useRef(1);
  const effectiveUserQueryRef = useRef<UserListQueryState | undefined>(userQuery);

  useEffect(() => {
    const rawSearch = userQuery?.searchQuery ?? '';
    const timer = setTimeout(() => {
      setDebouncedUserSearch(rawSearch);
    }, 250);
    return () => clearTimeout(timer);
  }, [userQuery?.searchQuery]);

  const effectiveUserQuery = useMemo<UserListQueryState | undefined>(
    () =>
      userQuery
        ? {
            ...userQuery,
            searchQuery: debouncedUserSearch,
          }
        : undefined,
    [userQuery, debouncedUserSearch],
  );

  useEffect(() => {
    effectiveUserQueryRef.current = effectiveUserQuery;
  }, [effectiveUserQuery]);

  const setUsersPage = useCallback((nextPage: number) => {
    const safe = Math.max(1, nextPage);
    usersPageRef.current = safe;
    setUsersPageState(safe);
  }, []);
  const [clearanceOptions, setClearanceOptions] = useState<ClearanceOptionRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [departmentLookup, setDepartmentLookup] = useState<DepartmentLookupRow[]>([]);
  const [businessCategories, setBusinessCategories] = useState<BusinessCategoryOptionRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);
  const [healthFetchError, setHealthFetchError] = useState<string | null>(null);

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
  const [message, setMessageState] = useState<string | null>(null);
  const [errorMessage, setErrorMessageState] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const setMessage = useCallback((next: string | null) => {
    setMessageState(next);
    if (next) {
      setErrorMessageState(null);
      setDialogError(null);
    }
  }, []);

  const setErrorMessage = useCallback((next: string | null) => {
    setErrorMessageState(next);
    if (next) {
      setMessageState(null);
    }
  }, []);

  const wm = useWatermarkSettings({
    onSuccess: (msg) => {
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
        setErrorMessageState(null);
      }

      const task = (async () => {
        if (tab === 'users') {
          usersAbortRef.current?.abort();
          const controller = new AbortController();
          usersAbortRef.current = controller;
          const seq = ++usersSeqRef.current;
          setIsLoadingUsers(true);

          const needDepartments =
            !departmentsLoadedRef.current || (!options?.silent && Boolean(options?.force));
          const needClearance =
            !clearanceLoadedRef.current || (!options?.silent && Boolean(options?.force));

          const targetPage = usersPageRef.current;
          const usersEndpoint = buildUsersEndpoint(effectiveUserQueryRef.current, targetPage);

          const [usersRes, deptsRes, clearanceOptsRes] = await Promise.allSettled([
            apiClient<UsersListResponse>(usersEndpoint, { signal: controller.signal }),
            needDepartments
              ? canManageDepartments
                ? apiClient<{ data: DepartmentRow[] }>('/departments')
                : apiClient<{ data: DepartmentLookupRow[] }>('/departments/lookup')
              : Promise.resolve(null),
            needClearance
              ? apiClient<{ data: ClearanceOptionRow[] }>('/users/clearance-options')
              : Promise.resolve(null),
          ]);

          if (usersSeqRef.current !== seq || controller.signal.aborted) {
            return;
          }
          setIsLoadingUsers(false);

          if (usersRes.status === 'fulfilled') {
            const list = usersRes.value.data || [];
            const resolvedTotal =
              typeof usersRes.value.total === 'number' ? usersRes.value.total : list.length;
            const resolvedTotalPages = Math.max(
              1,
              typeof usersRes.value.totalPages === 'number'
                ? usersRes.value.totalPages
                : Math.ceil(resolvedTotal / ADMIN_USERS_PAGE_SIZE),
            );
            setUsers(list);
            setUsersTotal(resolvedTotal);
            setUsersTotalPages(resolvedTotalPages);
            setUsersTruncated(Boolean(usersRes.value.truncated));
            if (targetPage > resolvedTotalPages) {
              usersPageRef.current = resolvedTotalPages;
              setUsersPageState(resolvedTotalPages);
            }
          }
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
                  parentId:
                    d.parentId !== undefined && d.parentId !== null ? String(d.parentId) : null,
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

          const nonAbortedResults = [usersRes, deptsRes, clearanceOptsRes].filter(
            (r) => r.status === 'fulfilled' || !isAbortErr(r.reason),
          );
          const errMsg = extractFirstRejectedError(
            nonAbortedResults,
            'Không thể tải danh sách tài khoản. Vui lòng thử lại.',
          );
          if (errMsg) {
            setErrorMessage(errMsg);
            return;
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
            markTabLoaded('departments');
          } else {
            setErrorMessage(
              extractFirstRejectedError(
                [deptsRes],
                'Không thể tải danh sách phòng ban. Vui lòng thử lại.',
              ),
            );
          }
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
              markTabLoaded('rbac');
            } else {
              setErrorMessage(
                extractFirstRejectedError(
                  [lookupRes],
                  'Không thể tải danh mục vai trò. Vui lòng thử lại.',
                ),
              );
            }
            return;
          }

          const [rolesRes, permsRes] = await Promise.allSettled([
            apiClient<{ data: RoleRow[] }>('/rbac/roles'),
            apiClient<{ data: PermissionRow[] }>('/rbac/permissions'),
          ]);
          if (rolesRes.status === 'fulfilled') {
            setRoles(rolesRes.value.data || []);
          }
          if (permsRes.status === 'fulfilled') {
            const loadedPerms = permsRes.value.data || [];
            setPermissions(loadedPerms);
            setPermissionsLoaded(true);
          } else {
            setPermissionsLoaded(false);
          }

          const errMsg = extractFirstRejectedError(
            [rolesRes, permsRes],
            'Không thể tải đầy đủ danh mục vai trò và quyền hạn. Vui lòng thử lại.',
          );
          if (errMsg) {
            setErrorMessage(errMsg);
            return;
          }
          markTabLoaded('rbac');
          return;
        }

        if (tab === 'abac') {
          const canLookupAbacDepartments =
            canManagePolicies || canSimulatePolicy || canManageDepartments;
          const needDeptLookup =
            canLookupAbacDepartments && (!departmentsLoadedRef.current || Boolean(options?.force));
          const canReadCategories = canManagePolicies || canSimulatePolicy;
          const needCategories =
            canReadCategories && (!categoriesLoadedRef.current || Boolean(options?.force));

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
            needCategories
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

          const errMsg = extractFirstRejectedError(
            [policiesRes, attrsRes, deptLookupRes, categoriesRes],
            'Không thể tải dữ liệu chính sách truy cập. Vui lòng thử lại.',
          );
          if (errMsg) {
            setErrorMessage(errMsg);
            return;
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
            markTabLoaded('watermark');
          } else {
            setErrorMessage(
              extractFirstRejectedError(
                [wmConfigsRes],
                'Không thể tải cấu hình watermark bảo mật. Vui lòng thử lại.',
              ),
            );
          }
          return;
        }

        if (tab === 'health') {
          try {
            const dashboardData = await apiClient<HealthDashboardResponse>('/health/dashboard');
            setHealthData(mapHealthReadyResponse(null, dashboardData));
            setHealthFetchError(null);
            markTabLoaded('health');
          } catch (err) {
            if (err instanceof ApiError && isGenuineHealthPayload(err.response)) {
              const raw = err.response;
              if ('dependencies' in raw) {
                setHealthData(
                  mapHealthReadyResponse(null, raw as unknown as HealthDashboardResponse),
                );
              } else {
                setHealthData(mapHealthReadyResponse(raw as unknown as HealthReadyResponse, null));
              }
              setHealthFetchError(null);
              markTabLoaded('health');
              return;
            }
            setHealthData(null);
            setHealthFetchError(
              err instanceof ApiError && err.message
                ? err.message
                : 'Không thể kết nối máy chủ để kiểm tra tình trạng hệ thống. Vui lòng kiểm tra đường truyền và thử lại.',
            );
          }
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
      setErrorMessage,
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

  // HIGH-21 (BUG-098): Tự động đồng bộ tìm kiếm, bộ lọc trạng thái/phòng ban và chuyển trang lên máy chủ GET /users để tiếp cận toàn bộ nhân sự > 200 mà không gỡ ô nhập tiếng Việt.
  const usersQuerySyncMountedRef = useRef(false);
  useEffect(() => {
    if (!usersQuerySyncMountedRef.current) {
      usersQuerySyncMountedRef.current = true;
      return;
    }
    if (activeTab !== 'users' || !loadedTabsRef.current.has('users')) {
      return;
    }
    void loadTab('users', { silent: true, force: true });
  }, [
    activeTab,
    usersPage,
    debouncedUserSearch,
    userQuery?.statusFilter,
    userQuery?.departmentFilter,
    userQuery?.actionFilter,
    loadTab,
  ]);

  useEffect(() => {
    return () => {
      usersAbortRef.current?.abort();
    };
  }, []);

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
    usersPage,
    setUsersPage,
    usersTotalPages,
    usersTotal,
    usersTruncated,
    isLoadingUsers,
    clearanceOptions,
    departments,
    abacDepartments,
    businessCategories,
    roles,
    permissions,
    permissionsLoaded,
    policies,
    attributes,
    healthData,
    healthFetchError,
    watermark: wm,
    loadedTabs,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    dialogError,
    setDialogError,
    ensureTabLoaded,
    refresh,
    ...mutations,
  };
}
