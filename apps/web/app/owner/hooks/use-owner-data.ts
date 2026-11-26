'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
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

const OWNER_DOCS_PAGE_SIZE = 50;
const OWNER_REQUESTS_PAGE_SIZE = 20;

function isOwnerAbortError(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return (
    (typeof DOMException !== 'undefined' &&
      err instanceof DOMException &&
      err.name === 'AbortError') ||
    (err instanceof Error && err.name === 'AbortError')
  );
}

/**
 * Thuật toán: Tải Lười Theo Tab, Tìm Kiếm Máy Chủ Có Giảm Chấn, `AbortController` Riêng & Bảo Toàn Banner Lỗi (`useOwnerData`, HIGH-19, MED-25)
 * Mục đích:
 *   - Chỉ nạp yêu cầu truy cập với quyền `ACCESS_REQUEST:DECIDE` (khớp 100% BE `scope=incoming`).
 *   - Tìm kiếm kho tài liệu trực tiếp trên máy chủ (`q=...`) với debounce 250ms, bảo vệ từng bộ nạp bằng `AbortController` + bộ đếm tuần tự và giữ ổn định kết nối SSE qua `auditPageRef`.
 *   - Không xóa `auditLogs` hoặc bật nháy spinner khi đồng bộ im lặng (`silent: true`) gặp lỗi, đồng thời kẹp trang tự động khi trang hiện tại (> 1) rỗng.
 */
export function useOwnerData(activeTab: OwnerTab | null, searchQuery = '') {
  const { hasPermission } = useAuth();
  const canDiscoverDocs = hasPermission('DOCUMENT:DISCOVER');
  const canLookupDepartments =
    hasPermission('DOCUMENT:UPLOAD') ||
    canDiscoverDocs ||
    hasPermission('DEPARTMENT:MANAGE') ||
    hasPermission('USER:MANAGE') ||
    hasPermission('POLICY:MANAGE') ||
    hasPermission('POLICY:SIMULATE') ||
    hasPermission('SYSTEM_REPORT:EXPORT') ||
    hasPermission('AUDIT_LOG:EXPORT');
  const canLookupClassifications =
    canDiscoverDocs ||
    hasPermission('DOCUMENT:UPLOAD') ||
    hasPermission('DOCUMENT:CLASSIFY') ||
    hasPermission('POLICY:MANAGE') ||
    hasPermission('POLICY:SIMULATE') ||
    hasPermission('AUDIT_LOG:VIEW') ||
    hasPermission('SECURITY_ALERT:VIEW');
  const canViewRequests = hasPermission('ACCESS_REQUEST:DECIDE');
  const canViewGrants = hasPermission('ACCESS_GRANT:VIEW');
  const canLookupUsers =
    hasPermission('ACCESS_GRANT:CREATE') ||
    hasPermission('DOCUMENT:MANAGE') ||
    hasPermission('USER:MANAGE');
  const canLookupRoles =
    hasPermission('ACCESS_GRANT:CREATE') ||
    hasPermission('USER:MANAGE') ||
    hasPermission('ROLE:MANAGE');
  const canViewAuditLogs = hasPermission('AUDIT_LOG:VIEW');

  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [docsPage, setDocsPage] = useState(1);
  const [docsHasMore, setDocsHasMore] = useState(false);
  const [isLoadingDocs, setIsLoadingDocs] = useState(false);
  const [activeOwnedDocuments, setActiveOwnedDocuments] = useState<DocumentItem[]>([]);
  const [isLoadingGrantDocs, setIsLoadingGrantDocs] = useState(false);

  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [requestsPage, setRequestsPage] = useState(1);
  const [requestsTotal, setRequestsTotal] = useState(0);
  const [isLoadingRequests, setIsLoadingRequests] = useState(false);

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
  const docsPageRef = useRef(1);
  const docsSearchRef = useRef('');
  const docsAbortRef = useRef<AbortController | null>(null);
  const docsSeqRef = useRef(0);
  const requestsPageRef = useRef(1);
  const requestsAbortRef = useRef<AbortController | null>(null);
  const requestsSeqRef = useRef(0);
  const grantsAbortRef = useRef<AbortController | null>(null);
  const grantsSeqRef = useRef(0);
  const auditPageRef = useRef(1);
  const auditAbortRef = useRef<AbortController | null>(null);
  const auditSeqRef = useRef(0);
  const activeOwnedDocsRef = useRef<DocumentItem[]>([]);
  const activeOwnedDocsLoadedRef = useRef(false);
  const inFlightGrantDocsRef = useRef<Promise<DocumentItem[]> | null>(null);
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

  const markTabLoaded = useCallback((tab: OwnerTab) => {
    if (!loadedTabsRef.current.has(tab)) {
      loadedTabsRef.current.add(tab);
      setLoadedTabs((prev) => (prev[tab] ? prev : { ...prev, [tab]: true }));
    }
  }, []);

  const syncGrantLookups = useCallback(() => {
    const mergedDocsById = new Map<string, DocumentItem>();
    for (const doc of activeOwnedDocsRef.current) mergedDocsById.set(doc.id, doc);
    for (const doc of docsRef.current) mergedDocsById.set(doc.id, doc);
    grantLookupsRef.current = buildGrantLookupMaps(
      [...mergedDocsById.values()],
      usersLookupRef.current,
      rolesLookupRef.current,
    );
  }, []);

  const ensureUploadLookups = useCallback(async () => {
    const needDepts = canLookupDepartments && !deptsLoadedRef.current;
    const needCats = canLookupClassifications && !catsLoadedRef.current;
    const needLevels = canLookupClassifications && !levelsLoadedRef.current;
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
      catsRef.current = catsRes.value.data || [];
      setBusinessCategories(catsRef.current);
      catsLoadedRef.current = true;
    }
    if (levelsRes.status === 'fulfilled' && levelsRes.value) {
      levelsRef.current = levelsRes.value.data || [];
      setClassificationLevels(levelsRef.current);
      levelsLoadedRef.current = true;
    }
  }, [canLookupClassifications, canLookupDepartments]);

  const ensureGrantLookups = useCallback(async () => {
    const needUsers = canLookupUsers && !usersLookupLoadedRef.current;
    const needRoles = canLookupRoles && !rolesLookupLoadedRef.current;
    if (!needUsers && !needRoles) return;

    const [usersRes, rolesRes] = await Promise.allSettled([
      needUsers ? apiClient<{ data: UserLookupItem[] }>('/users/lookup') : Promise.resolve(null),
      needRoles
        ? apiClient<{ data: RoleLookupItem[] }>('/rbac/roles/lookup')
        : Promise.resolve(null),
    ]);

    if (usersRes.status === 'fulfilled' && usersRes.value) {
      usersLookupRef.current = usersRes.value.data || [];
      setUsersLookup(usersLookupRef.current);
      usersLookupLoadedRef.current = true;
    }
    if (rolesRes.status === 'fulfilled' && rolesRes.value) {
      rolesLookupRef.current = rolesRes.value.data || [];
      setRolesLookup(rolesLookupRef.current);
      rolesLookupLoadedRef.current = true;
    }
    syncGrantLookups();
  }, [canLookupRoles, canLookupUsers, syncGrantLookups]);

  const ensureGrantDocuments = useCallback(async (): Promise<DocumentItem[]> => {
    if (!canDiscoverDocs) return docsRef.current.filter((d) => d.status === 'ACTIVE');
    if (activeOwnedDocsLoadedRef.current) return activeOwnedDocsRef.current;
    if (inFlightGrantDocsRef.current) return inFlightGrantDocsRef.current;

    setIsLoadingGrantDocs(true);
    const task = (async () => {
      const needCats = canLookupClassifications && !catsLoadedRef.current;
      const needLevels = canLookupClassifications && !levelsLoadedRef.current;
      const [activeDocsRes, catsRes, levelsRes] = await Promise.allSettled([
        apiClient<{ data: DocumentApiDto[] }>('/documents?scope=owned&status=ACTIVE&pageSize=50'),
        needCats
          ? apiClient<{ data: BusinessCategoryLookupItem[] }>('/classifications/categories')
          : Promise.resolve(null),
        needLevels
          ? apiClient<{ data: ClassificationLevelLookupItem[] }>('/classifications/levels')
          : Promise.resolve(null),
      ]);

      if (catsRes.status === 'fulfilled' && catsRes.value) {
        catsRef.current = catsRes.value.data || [];
        setBusinessCategories(catsRef.current);
        catsLoadedRef.current = true;
      }
      if (levelsRes.status === 'fulfilled' && levelsRes.value) {
        levelsRef.current = levelsRes.value.data || [];
        setClassificationLevels(levelsRef.current);
        levelsLoadedRef.current = true;
      }
      if (activeDocsRes.status === 'fulfilled') {
        const mappedActive = (activeDocsRes.value.data || []).map((d) =>
          mapDocumentDtoToItem(d, {
            businessCategories: catsRef.current,
            classificationLevels: levelsRef.current,
          }),
        );
        activeOwnedDocsRef.current = mappedActive;
        activeOwnedDocsLoadedRef.current = true;
        setActiveOwnedDocuments(mappedActive);
        syncGrantLookups();
        return mappedActive;
      }
      return docsRef.current.filter((d) => d.status === 'ACTIVE');
    })();

    inFlightGrantDocsRef.current = task;
    try {
      return await task;
    } finally {
      if (inFlightGrantDocsRef.current === task) inFlightGrantDocsRef.current = null;
      setIsLoadingGrantDocs(false);
    }
  }, [canDiscoverDocs, canLookupClassifications, syncGrantLookups]);

  const loadDocumentsPage = useCallback(
    async (page = 1, options?: { silent?: boolean; search?: string }): Promise<boolean> => {
      if (!canDiscoverDocs) return true;
      docsAbortRef.current?.abort();
      const controller = new AbortController();
      docsAbortRef.current = controller;
      const seq = ++docsSeqRef.current;

      let activePage = Math.max(1, page);
      const effectiveSearch = (options?.search ?? docsSearchRef.current).trim();
      docsPageRef.current = activePage;
      docsSearchRef.current = effectiveSearch;
      setDocsPage(activePage);
      if (!options?.silent) setIsLoadingDocs(true);
      try {
        const fetchDocsAtPage = async (targetPage: number) => {
          const params = new URLSearchParams({
            scope: 'owned',
            page: String(targetPage),
            pageSize: String(OWNER_DOCS_PAGE_SIZE),
          });
          if (effectiveSearch) {
            params.set('q', effectiveSearch);
          }
          return apiClient<{ data: DocumentApiDto[]; page?: number; hasMore?: boolean }>(
            `/documents?${params.toString()}`,
            { signal: controller.signal },
          );
        };

        let res = await fetchDocsAtPage(activePage);
        if (docsSeqRef.current !== seq || controller.signal.aborted) return false;
        let mappedDocs = (res.data || []).map((d) =>
          mapDocumentDtoToItem(d, {
            businessCategories: catsRef.current,
            classificationLevels: levelsRef.current,
          }),
        );
        if (activePage > 1 && mappedDocs.length === 0) {
          activePage -= 1;
          docsPageRef.current = activePage;
          res = await fetchDocsAtPage(activePage);
          if (docsSeqRef.current !== seq || controller.signal.aborted) return false;
          mappedDocs = (res.data || []).map((d) =>
            mapDocumentDtoToItem(d, {
              businessCategories: catsRef.current,
              classificationLevels: levelsRef.current,
            }),
          );
        }
        const docsMissingCategory = mappedDocs.filter(
          (doc) =>
            !doc.businessCategoryName || !doc.businessCategoryId || !doc.classificationLevelId,
        );
        if (docsMissingCategory.length > 0) {
          const detailResults = await Promise.allSettled(
            docsMissingCategory.map((doc) =>
              apiClient<DocumentApiDto>(`/documents/${doc.id}`, { signal: controller.signal }),
            ),
          );
          if (docsSeqRef.current !== seq || controller.signal.aborted) return false;
          const detailMap = new Map<string, DocumentApiDto>();
          detailResults.forEach((detailRes, idx) => {
            const targetDoc = docsMissingCategory[idx];
            if (detailRes.status === 'fulfilled' && targetDoc) {
              detailMap.set(targetDoc.id, detailRes.value);
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
                description: enriched.description ?? doc.description,
                classificationLevelId: enriched.classificationLevelId ?? doc.classificationLevelId,
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
        if (
          !effectiveSearch &&
          activePage === 1 &&
          !res.hasMore &&
          mappedDocs.length < OWNER_DOCS_PAGE_SIZE
        ) {
          const activeSubset = mappedDocs.filter((d) => d.status === 'ACTIVE');
          activeOwnedDocsRef.current = activeSubset;
          activeOwnedDocsLoadedRef.current = true;
          setActiveOwnedDocuments(activeSubset);
        } else if (!effectiveSearch) {
          activeOwnedDocsLoadedRef.current = false;
        }
        syncGrantLookups();
        setDocuments(mappedDocs);
        setDocsPage(res.page ?? activePage);
        setDocsHasMore(Boolean(res.hasMore));
        return true;
      } catch (err) {
        if (isOwnerAbortError(err, controller.signal) || docsSeqRef.current !== seq) return false;
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError && err.message
              ? err.message
              : 'Không thể tải danh sách tài liệu. Vui lòng thử lại.',
          );
        }
        return false;
      } finally {
        if (docsSeqRef.current === seq && !options?.silent) setIsLoadingDocs(false);
      }
    },
    [canDiscoverDocs, setErrorMessage, syncGrantLookups],
  );

  const loadRequestsPage = useCallback(
    async (page = 1, options?: { silent?: boolean }): Promise<boolean> => {
      if (!canViewRequests) return true;
      requestsAbortRef.current?.abort();
      const controller = new AbortController();
      requestsAbortRef.current = controller;
      const seq = ++requestsSeqRef.current;

      let activePage = Math.max(1, page);
      requestsPageRef.current = activePage;
      setRequestsPage(activePage);
      if (!options?.silent) setIsLoadingRequests(true);
      try {
        const fetchReqsAtPage = (targetPage: number) =>
          apiClient<{ data: AccessRequestItem[]; total?: number }>(
            `/access-requests?scope=incoming&status=PENDING&page=${targetPage}&pageSize=${OWNER_REQUESTS_PAGE_SIZE}`,
            { signal: controller.signal },
          );
        let res = await fetchReqsAtPage(activePage);
        if (requestsSeqRef.current !== seq || controller.signal.aborted) return false;
        let rows = res.data || [];
        let total = typeof res.total === 'number' ? res.total : rows.length;
        const maxPage = Math.max(1, Math.ceil(total / OWNER_REQUESTS_PAGE_SIZE));
        if (activePage > maxPage || (activePage > 1 && rows.length === 0)) {
          activePage = Math.min(maxPage, activePage - 1);
          requestsPageRef.current = activePage;
          setRequestsPage(activePage);
          res = await fetchReqsAtPage(activePage);
          if (requestsSeqRef.current !== seq || controller.signal.aborted) return false;
          rows = res.data || [];
          total = typeof res.total === 'number' ? res.total : rows.length;
        }
        setRequests(rows);
        setRequestsTotal(total);
        return true;
      } catch (err) {
        if (isOwnerAbortError(err, controller.signal) || requestsSeqRef.current !== seq) {
          return false;
        }
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError && err.message
              ? err.message
              : 'Không thể tải danh sách yêu cầu truy cập. Vui lòng thử lại.',
          );
        }
        return false;
      } finally {
        if (requestsSeqRef.current === seq && !options?.silent) setIsLoadingRequests(false);
      }
    },
    [canViewRequests, setErrorMessage],
  );

  const loadGrants = useCallback(
    async (
      page = 1,
      status: GrantStatusFilter = grantsStatusFilterRef.current,
      options?: { silent?: boolean },
    ): Promise<boolean> => {
      if (!canViewGrants) return true;
      grantsAbortRef.current?.abort();
      const controller = new AbortController();
      grantsAbortRef.current = controller;
      const seq = ++grantsSeqRef.current;

      let activePage = Math.max(1, page);
      grantsPageRef.current = activePage;
      grantsStatusFilterRef.current = status;
      setGrantsPage(activePage);
      setGrantsStatusFilter(status);
      if (!options?.silent) setIsLoadingGrants(true);
      try {
        const statusSuffix = status !== 'ALL' ? `&status=${status}` : '';
        const fetchGrantsAtPage = (targetPage: number) => {
          const pageSuffix = targetPage > 1 ? `&page=${targetPage}` : '';
          return apiClient<{
            data: AccessGrantApiDto[];
            page?: number;
            hasMore?: boolean;
          }>(`/access-grants?scope=owned&pageSize=50${pageSuffix}${statusSuffix}`, {
            signal: controller.signal,
          });
        };

        let [res, activeSummaryRes] = await Promise.all([
          fetchGrantsAtPage(activePage),
          status === 'ACTIVE' && activePage === 1
            ? Promise.resolve(null)
            : apiClient<{ data: AccessGrantApiDto[]; hasMore?: boolean }>(
                '/access-grants?scope=owned&status=ACTIVE&pageSize=50',
                { signal: controller.signal },
              ).catch(() => null),
        ]);
        if (grantsSeqRef.current !== seq || controller.signal.aborted) return false;
        let mapped = (res.data || []).map((g) => mapGrantDtoToItem(g, grantLookupsRef.current));
        if (activePage > 1 && mapped.length === 0) {
          activePage -= 1;
          grantsPageRef.current = activePage;
          res = await fetchGrantsAtPage(activePage);
          if (grantsSeqRef.current !== seq || controller.signal.aborted) return false;
          mapped = (res.data || []).map((g) => mapGrantDtoToItem(g, grantLookupsRef.current));
        }
        setGrants(mapped);
        setGrantsPage(res.page ?? activePage);
        setGrantsHasMore(Boolean(res.hasMore));
        if (status === 'ACTIVE' && activePage === 1) {
          setActiveGrantsCount(mapped.length);
        } else if (activeSummaryRes && Array.isArray(activeSummaryRes.data)) {
          setActiveGrantsCount(activeSummaryRes.data.length);
        } else if (activePage === 1 && status === 'ALL') {
          setActiveGrantsCount(mapped.filter((g) => g.status === 'ACTIVE').length);
        }
        return true;
      } catch (err) {
        if (isOwnerAbortError(err, controller.signal) || grantsSeqRef.current !== seq) return false;
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError && err.message
              ? err.message
              : 'Không thể tải danh sách quyền truy cập. Vui lòng thử lại.',
          );
        }
        return false;
      } finally {
        if (grantsSeqRef.current === seq && !options?.silent) setIsLoadingGrants(false);
      }
    },
    [canViewGrants, setErrorMessage],
  );

  const loadAuditLogs = useCallback(
    async (page = 1, options?: { silent?: boolean }): Promise<boolean> => {
      if (!canViewAuditLogs) return true;
      auditAbortRef.current?.abort();
      const controller = new AbortController();
      auditAbortRef.current = controller;
      const seq = ++auditSeqRef.current;

      const safePage = Math.max(1, page);
      auditPageRef.current = safePage;
      if (!options?.silent) setIsLoadingAudit(true);
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
        }>(`/audit-logs?page=${safePage}&pageSize=15`, { signal: controller.signal });
        if (auditSeqRef.current !== seq || controller.signal.aborted) return false;
        const pageMeta = extractAuditPagination(res);
        setAuditLogs(res.data || []);
        setAuditPage(pageMeta.page);
        auditPageRef.current = pageMeta.page;
        setAuditTotalPages(pageMeta.totalPages);
        setAuditTotal(pageMeta.total);
        return true;
      } catch (err) {
        if (isOwnerAbortError(err, controller.signal) || auditSeqRef.current !== seq) return false;
        if (!options?.silent) {
          setAuditLogs([]);
          setErrorMessage(
            err instanceof ApiError && err.message
              ? err.message
              : 'Không thể tải lịch sử kiểm toán tài liệu. Vui lòng thử lại.',
          );
        }
        return false;
      } finally {
        if (auditSeqRef.current === seq && !options?.silent) setIsLoadingAudit(false);
      }
    },
    [canViewAuditLogs, setErrorMessage],
  );

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
        setErrorMessageState(null);
      }

      const task = (async () => {
        if (tab === 'documents') {
          if (!canDiscoverDocs) {
            markTabLoaded('documents');
            return;
          }
          const needCats =
            canLookupClassifications &&
            (!catsLoadedRef.current || (!options?.silent && Boolean(options?.force)));
          const needLevels =
            canLookupClassifications &&
            (!levelsLoadedRef.current || (!options?.silent && Boolean(options?.force)));

          const [catsResult, levelsResult] = await Promise.allSettled([
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

          const docsOk = await loadDocumentsPage(docsPageRef.current, {
            silent: Boolean(options?.silent),
          });
          if (docsOk) {
            markTabLoaded('documents');
          }
          return;
        }

        if (tab === 'requests') {
          if (!canViewRequests) {
            markTabLoaded('requests');
            return;
          }
          const reqOk = await loadRequestsPage(requestsPageRef.current, {
            silent: Boolean(options?.silent),
          });
          if (reqOk) {
            markTabLoaded('requests');
          }
          return;
        }

        if (tab === 'grants') {
          if (!canViewGrants) {
            markTabLoaded('grants');
            return;
          }
          await ensureGrantLookups();
          syncGrantLookups();
          const grantsOk = await loadGrants(grantsPageRef.current, grantsStatusFilterRef.current, {
            silent: Boolean(options?.silent),
          });
          if (grantsOk) markTabLoaded('grants');
          return;
        }

        if (tab === 'history') {
          if (!canViewAuditLogs) {
            markTabLoaded('history');
            return;
          }
          const auditOk = await loadAuditLogs(auditPageRef.current, {
            silent: Boolean(options?.silent),
          });
          if (auditOk) {
            markTabLoaded('history');
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
      canDiscoverDocs,
      canLookupClassifications,
      canViewAuditLogs,
      canViewGrants,
      canViewRequests,
      ensureGrantLookups,
      loadAuditLogs,
      loadDocumentsPage,
      loadGrants,
      loadRequestsPage,
      markTabLoaded,
      syncGrantLookups,
    ],
  );

  const refreshData = useCallback(
    async (options?: { silent?: boolean; scope?: OwnerTab }) => {
      const targetTab = options?.scope ?? activeTab;
      if (!targetTab) {
        setIsLoading(false);
        return;
      }
      await loadTab(targetTab, {
        ...(options?.silent !== undefined ? { silent: options.silent } : {}),
        force: true,
      });
    },
    [activeTab, loadTab],
  );

  const invalidateGrants = useCallback(async () => {
    activeOwnedDocsLoadedRef.current = false;
    if (!canViewGrants) return;
    if (loadedTabsRef.current.has('grants')) {
      await loadTab('grants', { silent: true, force: true });
    } else {
      loadedTabsRef.current.delete('grants');
    }
  }, [canViewGrants, loadTab]);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        if (!activeTab || loadedTabsRef.current.has(activeTab)) {
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
    const trimmed = searchQuery.trim();
    if (!loadedTabsRef.current.has('documents')) {
      docsSearchRef.current = trimmed;
      return;
    }
    if (trimmed === docsSearchRef.current) return;
    const timer = setTimeout(() => {
      void loadDocumentsPage(1, { search: trimmed });
    }, 250);
    return () => clearTimeout(timer);
  }, [loadDocumentsPage, searchQuery]);

  useEffect(() => {
    return () => {
      docsAbortRef.current?.abort();
      requestsAbortRef.current?.abort();
      grantsAbortRef.current?.abort();
      auditAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    let reqTimer: ReturnType<typeof setTimeout> | null = null;
    let grantTimer: ReturnType<typeof setTimeout> | null = null;

    const unsubRequests = subscribeRealtimeEvent('ACCESS_REQUEST_UPDATED', () => {
      if (!canViewRequests) return;
      if (reqTimer) clearTimeout(reqTimer);
      reqTimer = setTimeout(() => {
        reqTimer = null;
        void loadTab('requests', { silent: true, force: true });
      }, 120);
    });

    const unsubGrants = subscribeRealtimeEvent('ACCESS_GRANT_UPDATED', () => {
      if (!canViewGrants || !loadedTabsRef.current.has('grants')) return;
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
  }, [canViewGrants, canViewRequests, loadTab]);

  return {
    documents,
    setDocuments,
    docsPage,
    docsHasMore,
    isLoadingDocs,
    loadDocumentsPage,
    activeOwnedDocuments,
    isLoadingGrantDocs,
    requests,
    setRequests,
    requestsPage,
    requestsTotal,
    setRequestsTotal,
    requestsTotalPages: Math.max(1, Math.ceil(requestsTotal / OWNER_REQUESTS_PAGE_SIZE)),
    requestsHasMore: requestsPage * OWNER_REQUESTS_PAGE_SIZE < requestsTotal,
    isLoadingRequests,
    loadRequestsPage,
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
    dialogError,
    setDialogError,
    loadAuditLogs,
    ensureUploadLookups,
    ensureGrantLookups,
    ensureGrantDocuments,
    invalidateGrants,
    refreshData,
  };
}
