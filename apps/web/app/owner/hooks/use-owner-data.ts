'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { apiClient } from '@/lib/api-client';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import {
  buildGrantLookupMaps,
  extractAuditPagination,
  mapDocumentDtoToItem,
  mapGrantDtoToItem,
} from '../helpers';
import type {
  AccessGrantApiDto,
  AccessGrantItem,
  AccessRequestItem,
  AuditLogItem,
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
  DocumentApiDto,
  DocumentItem,
  GrantLookupMaps,
  GrantStatusFilter,
  RoleLookupItem,
  UserLookupItem,
} from '../types';

export type OwnerTab = 'documents' | 'requests' | 'grants' | 'history';

/**
 * Thuật toán: Tải Lười Theo Tab, Tra Cứu Theo Nhu Cầu & Đồng Bộ SSE Realtime Cho Không Gian Chủ Sở Hữu (`useOwnerData`)
 * Mục đích:
 *   - Giảm tải khởi tạo `/owner` từ 9 lời gọi API xuống còn 3 lời gọi cốt lõi cho tab `documents` (`/documents`, `/classifications/categories`, `/classifications/levels`).
 *   - Chỉ tải `requests`, `grants`, `audit-logs`, `/departments/lookup`, `/users/lookup`, `/rbac/roles/lookup` khi người dùng chuyển đúng tab hoặc mở hộp thoại tương ứng.
 *   - Lắng nghe sự kiện SSE `ACCESS_REQUEST_UPDATED` và `ACCESS_GRANT_UPDATED` để cập nhật tức thời hàng đợi yêu cầu từ `/reader` và danh sách quyền truy cập mà không cần F5.
 */
export function useOwnerData(activeTab: OwnerTab) {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);
  const [grantsPage, setGrantsPage] = useState(1);
  const [grantsHasMore, setGrantsHasMore] = useState(false);
  const [grantsStatusFilter, setGrantsStatusFilter] = useState<GrantStatusFilter>('ALL');
  const [isLoadingGrants, setIsLoadingGrants] = useState(false);
  const [activeGrantsCount, setActiveGrantsCount] = useState(0);

  const [departments, setDepartments] = useState<DepartmentLookupItem[]>([]);
  const [businessCategories, setBusinessCategories] = useState<BusinessCategoryLookupItem[]>([]);
  const [classificationLevels, setClassificationLevels] = useState<ClassificationLevelLookupItem[]>(
    [],
  );
  const [usersLookup, setUsersLookup] = useState<UserLookupItem[]>([]);
  const [rolesLookup, setRolesLookup] = useState<RoleLookupItem[]>([]);

  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotalPages, setAuditTotalPages] = useState(1);
  const [auditTotal, setAuditTotal] = useState(0);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLogItem | null>(null);
  const [auditDetailOpen, setAuditDetailOpen] = useState(false);

  const [loadedTabs, setLoadedTabs] = useState<Partial<Record<OwnerTab, boolean>>>({});
  const loadedTabsRef = useRef<Set<OwnerTab>>(new Set());
  const inFlightTabsRef = useRef<Map<OwnerTab, Promise<void>>>(new Map());

  const docsRef = useRef<DocumentItem[]>([]);
  const catsRef = useRef<BusinessCategoryLookupItem[]>([]);
  const levelsRef = useRef<ClassificationLevelLookupItem[]>([]);
  const usersLookupRef = useRef<UserLookupItem[]>([]);
  const rolesLookupRef = useRef<RoleLookupItem[]>([]);
  const grantLookupsRef = useRef<GrantLookupMaps>({});
  const grantsPageRef = useRef(1);
  const grantsStatusFilterRef = useRef<GrantStatusFilter>('ALL');

  const catsLoadedRef = useRef(false);
  const levelsLoadedRef = useRef(false);
  const deptsLoadedRef = useRef(false);
  const usersLookupLoadedRef = useRef(false);
  const rolesLookupLoadedRef = useRef(false);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const markTabLoaded = useCallback((tab: OwnerTab) => {
    if (!loadedTabsRef.current.has(tab)) {
      loadedTabsRef.current.add(tab);
      setLoadedTabs((prev) => (prev[tab] ? prev : { ...prev, [tab]: true }));
    }
  }, []);

  const syncGrantLookups = useCallback(() => {
    grantLookupsRef.current = buildGrantLookupMaps(
      docsRef.current,
      usersLookupRef.current,
      rolesLookupRef.current,
    );
  }, []);

  const ensureUploadLookups = useCallback(async () => {
    const needDepts = !deptsLoadedRef.current;
    const needCats = !catsLoadedRef.current;
    const needLevels = !levelsLoadedRef.current;
    if (!needDepts && !needCats && !needLevels) return;

    const [deptsRes, catsRes, levelsRes] = await Promise.allSettled([
      needDepts
        ? apiClient<{ data: DepartmentLookupItem[] }>('/departments/lookup')
        : Promise.resolve(null),
      needCats
        ? apiClient<{ data: BusinessCategoryLookupItem[] }>('/classifications/categories')
        : Promise.resolve(null),
      needLevels
        ? apiClient<{ data: ClassificationLevelLookupItem[] }>('/classifications/levels')
        : Promise.resolve(null),
    ]);

    if (deptsRes.status === 'fulfilled' && deptsRes.value) {
      setDepartments(deptsRes.value.data || []);
      deptsLoadedRef.current = true;
    }
    if (catsRes.status === 'fulfilled' && catsRes.value) {
      const next = catsRes.value.data || [];
      catsRef.current = next;
      setBusinessCategories(next);
      catsLoadedRef.current = true;
    }
    if (levelsRes.status === 'fulfilled' && levelsRes.value) {
      const next = levelsRes.value.data || [];
      levelsRef.current = next;
      setClassificationLevels(next);
      levelsLoadedRef.current = true;
    }
  }, []);

  const ensureGrantLookups = useCallback(async () => {
    const needUsers = !usersLookupLoadedRef.current;
    const needRoles = !rolesLookupLoadedRef.current;
    if (!needUsers && !needRoles) return;

    const [usersRes, rolesRes] = await Promise.allSettled([
      needUsers ? apiClient<{ data: UserLookupItem[] }>('/users/lookup') : Promise.resolve(null),
      needRoles
        ? apiClient<{ data: RoleLookupItem[] }>('/rbac/roles/lookup')
        : Promise.resolve(null),
    ]);

    if (usersRes.status === 'fulfilled' && usersRes.value) {
      const next = usersRes.value.data || [];
      usersLookupRef.current = next;
      setUsersLookup(next);
      usersLookupLoadedRef.current = true;
    }
    if (rolesRes.status === 'fulfilled' && rolesRes.value) {
      const next = rolesRes.value.data || [];
      rolesLookupRef.current = next;
      setRolesLookup(next);
      rolesLookupLoadedRef.current = true;
    }
    syncGrantLookups();
  }, [syncGrantLookups]);

  const loadGrants = useCallback(
    async (page = 1, status: GrantStatusFilter = grantsStatusFilterRef.current) => {
      const safePage = Math.max(1, page);
      grantsPageRef.current = safePage;
      grantsStatusFilterRef.current = status;
      setGrantsPage(safePage);
      setGrantsStatusFilter(status);
      setIsLoadingGrants(true);
      try {
        const pageSuffix = safePage > 1 ? `&page=${safePage}` : '';
        const statusSuffix = status !== 'ALL' ? `&status=${status}` : '';
        const res = await apiClient<{
          data: AccessGrantApiDto[];
          page?: number;
          hasMore?: boolean;
        }>(`/access-grants?scope=owned&pageSize=50${pageSuffix}${statusSuffix}`);
        const mapped = (res.data || []).map((g) => mapGrantDtoToItem(g, grantLookupsRef.current));
        setGrants(mapped);
        setGrantsPage(res.page ?? safePage);
        setGrantsHasMore(Boolean(res.hasMore));
        if (safePage === 1 && status === 'ALL') {
          setActiveGrantsCount(mapped.filter((g) => g.status === 'ACTIVE').length);
        } else if (safePage === 1 && status === 'ACTIVE') {
          setActiveGrantsCount(mapped.length);
        }
      } catch {
        setErrorMessage('Không thể tải danh sách quyền truy cập. Vui lòng thử lại.');
      } finally {
        setIsLoadingGrants(false);
      }
    },
    [],
  );

  const loadAuditLogs = useCallback(async (page = 1) => {
    setIsLoadingAudit(true);
    try {
      const res = await apiClient<{
        data: AuditLogItem[];
        total?: number;
        page?: number;
        pageSize?: number;
        totalPages?: number;
        pagination?: {
          page?: number;
          pageSize?: number;
          total?: number;
          totalPages?: number;
        };
      }>(`/audit-logs?page=${page}&pageSize=15`);
      const pageMeta = extractAuditPagination(res);
      setAuditLogs(res.data || []);
      setAuditPage(pageMeta.page);
      setAuditTotalPages(pageMeta.totalPages);
      setAuditTotal(pageMeta.total);
    } catch {
      setAuditLogs([]);
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  const loadTab = useCallback(
    async (tab: OwnerTab, options?: { silent?: boolean; force?: boolean }) => {
      if (!options?.force && loadedTabsRef.current.has(tab)) return;
      const existing = inFlightTabsRef.current.get(tab);
      if (existing && !options?.force) {
        await existing;
        return;
      }

      if (!options?.silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);

      const task = (async () => {
        if (tab === 'documents') {
          const needCats = !catsLoadedRef.current || (!options?.silent && options?.force);
          const needLevels = !levelsLoadedRef.current || (!options?.silent && options?.force);

          const [docsResult, catsResult, levelsResult] = await Promise.allSettled([
            apiClient<{ data: DocumentApiDto[] }>('/documents?scope=owned&pageSize=50'),
            needCats
              ? apiClient<{ data: BusinessCategoryLookupItem[] }>('/classifications/categories')
              : Promise.resolve(null),
            needLevels
              ? apiClient<{ data: ClassificationLevelLookupItem[] }>('/classifications/levels')
              : Promise.resolve(null),
          ]);

          if (catsResult.status === 'fulfilled' && catsResult.value) {
            catsRef.current = catsResult.value.data || [];
            setBusinessCategories(catsRef.current);
            catsLoadedRef.current = true;
          }
          if (levelsResult.status === 'fulfilled' && levelsResult.value) {
            levelsRef.current = levelsResult.value.data || [];
            setClassificationLevels(levelsRef.current);
            levelsLoadedRef.current = true;
          }

          if (docsResult.status === 'fulfilled') {
            let mappedDocs = (docsResult.value.data || []).map((d) =>
              mapDocumentDtoToItem(d, {
                businessCategories: catsRef.current,
                classificationLevels: levelsRef.current,
              }),
            );
            const docsMissingCategory = mappedDocs.filter(
              (doc) =>
                !doc.businessCategoryName || !doc.businessCategoryId || !doc.classificationLevelId,
            );
            if (docsMissingCategory.length > 0) {
              const detailResults = await Promise.allSettled(
                docsMissingCategory.map((doc) => apiClient<DocumentApiDto>(`/documents/${doc.id}`)),
              );
              const detailMap = new Map<string, DocumentApiDto>();
              detailResults.forEach((res, idx) => {
                const targetDoc = docsMissingCategory[idx];
                if (res.status === 'fulfilled' && targetDoc) {
                  detailMap.set(targetDoc.id, res.value);
                }
              });
              if (detailMap.size > 0) {
                mappedDocs = mappedDocs.map((doc) => {
                  const detail = detailMap.get(doc.id);
                  if (!detail) return doc;
                  const enriched = mapDocumentDtoToItem(detail, {
                    businessCategories: catsRef.current,
                    classificationLevels: levelsRef.current,
                  });
                  return {
                    ...doc,
                    classificationLevelId:
                      enriched.classificationLevelId ?? doc.classificationLevelId,
                    businessCategoryId: enriched.businessCategoryId ?? doc.businessCategoryId,
                    businessCategoryCode: enriched.businessCategoryCode ?? doc.businessCategoryCode,
                    businessCategoryName: enriched.businessCategoryName ?? doc.businessCategoryName,
                    departmentId: enriched.departmentId ?? doc.departmentId,
                    departmentName:
                      doc.departmentName && doc.departmentName !== '—'
                        ? doc.departmentName
                        : enriched.departmentName,
                  };
                });
              }
            }
            docsRef.current = mappedDocs;
            syncGrantLookups();
            setDocuments(mappedDocs);
          } else {
            setErrorMessage('Không thể tải danh sách tài liệu. Vui lòng thử lại.');
          }
          markTabLoaded('documents');
          return;
        }

        if (tab === 'requests') {
          const [requestsResult] = await Promise.allSettled([
            apiClient<{ data: AccessRequestItem[] }>(
              '/access-requests?scope=incoming&status=PENDING',
            ),
          ]);
          if (requestsResult.status === 'fulfilled') {
            setRequests(requestsResult.value.data || []);
          }
          markTabLoaded('requests');
          return;
        }

        if (tab === 'grants') {
          const [, grantsResult] = await Promise.allSettled([
            ensureGrantLookups(),
            apiClient<{ data: AccessGrantApiDto[]; page?: number; hasMore?: boolean }>(
              '/access-grants?scope=owned&pageSize=50',
            ),
          ]);
          syncGrantLookups();
          if (grantsResult.status === 'fulfilled') {
            const mappedAll = (grantsResult.value.data || []).map((g) =>
              mapGrantDtoToItem(g, grantLookupsRef.current),
            );
            setActiveGrantsCount(mappedAll.filter((g) => g.status === 'ACTIVE').length);
            if (grantsPageRef.current === 1 && grantsStatusFilterRef.current === 'ALL') {
              setGrants(mappedAll);
              setGrantsPage(grantsResult.value.page ?? 1);
              setGrantsHasMore(Boolean(grantsResult.value.hasMore));
            } else {
              await loadGrants(grantsPageRef.current, grantsStatusFilterRef.current);
            }
          }
          markTabLoaded('grants');
          return;
        }

        if (tab === 'history') {
          await loadAuditLogs(1);
          markTabLoaded('history');
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
    [ensureGrantLookups, loadAuditLogs, loadGrants, markTabLoaded, syncGrantLookups],
  );

  const refreshData = useCallback(
    (options?: { silent?: boolean; scope?: OwnerTab }) =>
      loadTab(options?.scope ?? activeTab, {
        ...(options?.silent !== undefined ? { silent: options.silent } : {}),
        force: true,
      }),
    [activeTab, loadTab],
  );

  const invalidateGrants = useCallback(async () => {
    if (loadedTabsRef.current.has('grants')) {
      await loadTab('grants', { silent: true, force: true });
    }
  }, [loadTab]);

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

  useEffect(() => {
    let reqTimer: ReturnType<typeof setTimeout> | null = null;
    let grantTimer: ReturnType<typeof setTimeout> | null = null;

    const unsubRequests = subscribeRealtimeEvent('ACCESS_REQUEST_UPDATED', () => {
      if (reqTimer) clearTimeout(reqTimer);
      reqTimer = setTimeout(() => {
        reqTimer = null;
        void loadTab('requests', { silent: true, force: true });
      }, 120);
    });

    const unsubGrants = subscribeRealtimeEvent('ACCESS_GRANT_UPDATED', () => {
      if (!loadedTabsRef.current.has('grants')) return;
      if (grantTimer) clearTimeout(grantTimer);
      grantTimer = setTimeout(() => {
        grantTimer = null;
        void loadTab('grants', { silent: true, force: true });
      }, 120);
    });

    return () => {
      unsubRequests();
      unsubGrants();
      if (reqTimer) clearTimeout(reqTimer);
      if (grantTimer) clearTimeout(grantTimer);
    };
  }, [loadTab]);

  return {
    documents,
    setDocuments,
    requests,
    setRequests,
    grants,
    setGrants,
    grantsPage,
    grantsHasMore,
    grantsStatusFilter,
    isLoadingGrants,
    activeGrantsCount,
    setActiveGrantsCount,
    loadGrants,
    departments,
    businessCategories,
    classificationLevels,
    usersLookup,
    rolesLookup,
    auditLogs,
    auditPage,
    auditTotalPages,
    auditTotal,
    isLoadingAudit,
    selectedAuditLog,
    setSelectedAuditLog,
    auditDetailOpen,
    setAuditDetailOpen,
    loadedTabs,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    loadAuditLogs,
    ensureUploadLookups,
    ensureGrantLookups,
    invalidateGrants,
    refreshData,
  };
}
