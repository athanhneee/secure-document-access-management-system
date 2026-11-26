'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import {
  buildActiveGrantsByDocId,
  extractPendingRequestDocIds,
  mapReaderDocumentDto,
  mergeActiveReaderGrants,
} from '../helpers';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  MyRequestItem,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from '../types';
import { useReaderRequestActions } from './use-reader-request-actions';

const READER_PAGE_SIZE = 20;
const READER_LOOKUP_PAGE_SIZE = 50;
const MAX_LOOKUP_PAGES = 3;

interface PagedDocsResponse {
  data: ReaderDocumentApiDto[];
  page?: number;
  pageSize?: number;
  hasMore?: boolean;
}

interface PagedGrantsResponse {
  data: ReaderGrantApiDto[];
  page?: number;
  pageSize?: number;
  hasMore?: boolean;
}

interface PagedRequestsResponse {
  data: MyRequestItem[];
  total?: number;
}

function buildGrantedDocsSignature(docs: ReadonlyArray<MyGrantedDoc>): string {
  return docs
    .map(
      (d) =>
        `${d.documentId}|${d.id}|${[...d.permissions].sort().join(',')}|${d.validUntil}|${d.principalType}|${d.hasDirectAndRoleGrant ? '1' : '0'}`,
    )
    .join(';');
}

function buildGrantedMapSignature(map: ReadonlyMap<string, MyGrantedDoc>): string {
  return [...map.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(
      ([docId, d]) =>
        `${docId}|${d.id}|${[...d.permissions].sort().join(',')}|${d.validUntil}|${d.principalType}|${d.hasDirectAndRoleGrant ? '1' : '0'}`,
    )
    .join(';');
}

/**
 * Thuật toán: Nhận Diện Lỗi Hủy Yêu Cầu Chủ Động Qua `AbortController` (`isAbortError`, BUG-103)
 */
function isAbortError(err: unknown): boolean {
  return (
    (typeof DOMException !== 'undefined' &&
      err instanceof DOMException &&
      err.name === 'AbortError') ||
    (err instanceof Error && err.name === 'AbortError')
  );
}

/**
 * Thuật toán: Tải Độc Lập 3 Phân Khu Người Đọc Có `AbortController`, Hợp Quyền Theo Tài Liệu & Giữ Vững Banner (`useReaderCatalog`, BUG-102, BUG-103, BUG-119)
 * Mục đích:
 *   - Tách thành 3 bộ nạp độc lập (`loadCatalog`, `loadGrantedDocs`, `loadMyRequests`) gắn `AbortController` riêng để gõ tìm kiếm hay đổi bộ lọc 1 tab không bao giờ tải lại 2 tab còn lại hoặc làm mất tiêu điểm ô nhập.
 *   - Khi tìm kiếm trả lỗi `400` (từ khóa không hợp lệ như `***`) hoặc lỗi API, xóa sạch `discoverDocs = []` thay vì để sót kết quả cũ gây hiểu nhầm (`BUG-103`).
 *   - Hợp nhất quyền hiệu lực (`VIEW`/`DOWNLOAD`, `validUntil` xa nhất, `USER` + `ROLE`) theo `documentId` qua `mergeActiveReaderGrants` để loại bỏ dòng trùng khóa (`BUG-119`).
 *   - Đảm bảo loại trừ lẫn nhau giữa `message` và `errorMessage`, tách riêng `dialogError` của modal và chỉ xóa `errorMessage` khi `!options?.silent` để SSE nền không làm mất cảnh báo đang đọc (`BUG-102`).
 */
export function useReaderCatalog() {
  const { hasPermission } = useAuth();
  const canDiscover = hasPermission('DOCUMENT:DISCOVER');
  const canViewDocument = hasPermission('DOCUMENT:VIEW');
  const canViewOwnRequests = hasPermission('ACCESS_REQUEST:VIEW_OWN');

  const [discoverDocs, setDiscoverDocs] = useState<DiscoverableDoc[]>([]);
  const [discoverPage, setDiscoverPage] = useState(1);
  const [discoverHasMore, setDiscoverHasMore] = useState(false);
  const [isLoadingCatalog, setIsLoadingCatalog] = useState(true);

  const [myDocs, setMyDocs] = useState<MyGrantedDoc[]>([]);
  const [grantsPage, setGrantsPage] = useState(1);
  const [grantsHasMore, setGrantsHasMore] = useState(false);
  const [activeGrantsByDocId, setActiveGrantsByDocId] = useState<ReadonlyMap<string, MyGrantedDoc>>(
    () => new Map<string, MyGrantedDoc>(),
  );
  const [isLoadingGrants, setIsLoadingGrants] = useState(true);

  const [myRequests, setMyRequests] = useState<MyRequestItem[]>([]);
  const [requestsPage, setRequestsPage] = useState(1);
  const [requestsTotal, setRequestsTotal] = useState(0);
  const [requestStatusFilter, setRequestStatusFilter] = useState<string>('ALL');
  const [pendingRequestDocIds, setPendingRequestDocIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  );
  const [isLoadingRequests, setIsLoadingRequests] = useState(true);

  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');

  const [message, setMessageState] = useState<string | null>(null);
  const [errorMessage, setErrorMessageState] = useState<string | null>(null);

  const rawGrantsRef = useRef<ReaderGrantApiDto[]>([]);
  const rawAllGrantsRef = useRef<ReaderGrantApiDto[]>([]);
  const catalogAbortRef = useRef<AbortController | null>(null);
  const grantsAbortRef = useRef<AbortController | null>(null);
  const requestsAbortRef = useRef<AbortController | null>(null);
  const catalogSeqRef = useRef(0);
  const grantsSeqRef = useRef(0);
  const requestsSeqRef = useRef(0);

  const setMessage = useCallback((next: string | null) => {
    setMessageState(next);
    if (next) setErrorMessageState(null);
  }, []);

  const setErrorMessage = useCallback((next: string | null) => {
    setErrorMessageState(next);
    if (next) setMessageState(null);
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchQuery.trim());
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const handleSearchChange = useCallback((value: string) => {
    setSearchQuery(value);
    setDiscoverPage(1);
  }, []);

  const handleClassificationChange = useCallback((value: string) => {
    setSelectedClassification(value);
    setDiscoverPage(1);
  }, []);

  const handleRequestStatusFilterChange = useCallback((value: string) => {
    setRequestStatusFilter(value);
    setRequestsPage(1);
  }, []);

  const buildDiscoverEndpoint = useCallback((page: number, q: string, cls: string) => {
    const params = new URLSearchParams({
      status: 'ACTIVE',
      page: String(page),
      pageSize: String(READER_PAGE_SIZE),
    });
    if (q) params.set('q', q);
    if (cls && cls !== 'ALL') params.set('classificationCode', cls);
    return `/documents?${params.toString()}`;
  }, []);

  const buildRequestsEndpoint = useCallback((page: number, statusFilter: string) => {
    const params = new URLSearchParams({
      scope: 'my',
      page: String(page),
      pageSize: String(READER_PAGE_SIZE),
    });
    if (statusFilter && statusFilter !== 'ALL') {
      params.set('status', statusFilter);
    }
    return `/access-requests?${params.toString()}`;
  }, []);

  const fetchBoundedActiveGrantsLookup = useCallback(
    async (signal: AbortSignal): Promise<ReaderGrantApiDto[]> => {
      const collected: ReaderGrantApiDto[] = [];
      for (let pageNo = 1; pageNo <= MAX_LOOKUP_PAGES; pageNo += 1) {
        const res = await apiClient<PagedGrantsResponse>(
          `/documents/my-grants?page=${pageNo}&pageSize=${READER_LOOKUP_PAGE_SIZE}`,
          { signal },
        );
        const batch = res.data || [];
        collected.push(...batch);
        if (!res.hasMore || batch.length < READER_LOOKUP_PAGE_SIZE) {
          break;
        }
      }
      return collected;
    },
    [],
  );

  const fetchBoundedPendingRequestDocIds = useCallback(
    async (signal: AbortSignal): Promise<Set<string>> => {
      const ids = new Set<string>();
      for (let pageNo = 1; pageNo <= MAX_LOOKUP_PAGES; pageNo += 1) {
        const res = await apiClient<PagedRequestsResponse>(
          `/access-requests?scope=my&status=PENDING&page=${pageNo}&pageSize=${READER_LOOKUP_PAGE_SIZE}`,
          { signal },
        );
        const rows = res.data || [];
        for (const req of rows) {
          if (req.status === 'PENDING' && req.documentId) {
            ids.add(req.documentId);
          }
        }
        const total = typeof res.total === 'number' ? res.total : rows.length;
        if (pageNo * READER_LOOKUP_PAGE_SIZE >= total || rows.length < READER_LOOKUP_PAGE_SIZE) {
          break;
        }
      }
      return ids;
    },
    [],
  );

  const loadCatalog = useCallback(
    async (options?: { silent?: boolean }) => {
      catalogAbortRef.current?.abort();
      if (!canDiscover) {
        setDiscoverDocs([]);
        setDiscoverHasMore(false);
        setIsLoadingCatalog(false);
        return;
      }
      const controller = new AbortController();
      catalogAbortRef.current = controller;
      const seq = ++catalogSeqRef.current;

      setIsLoadingCatalog(true);
      if (!options?.silent) {
        setErrorMessageState(null);
      }

      try {
        const res = await apiClient<PagedDocsResponse>(
          buildDiscoverEndpoint(discoverPage, debouncedSearch, selectedClassification),
          { signal: controller.signal },
        );
        if (catalogSeqRef.current !== seq || controller.signal.aborted) return;
        setDiscoverDocs((res.data || []).map(mapReaderDocumentDto));
        setDiscoverHasMore(Boolean(res.hasMore));
      } catch (err) {
        if (isAbortError(err) || controller.signal.aborted || catalogSeqRef.current !== seq) {
          return;
        }
        setDiscoverDocs([]);
        setDiscoverHasMore(false);
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải danh mục tài liệu.',
          );
        }
      } finally {
        if (catalogSeqRef.current === seq) {
          setIsLoadingCatalog(false);
        }
      }
    },
    [
      canDiscover,
      discoverPage,
      debouncedSearch,
      selectedClassification,
      buildDiscoverEndpoint,
      setErrorMessage,
    ],
  );

  const loadGrantedDocs = useCallback(
    async (options?: { silent?: boolean }) => {
      grantsAbortRef.current?.abort();
      if (!canViewDocument) {
        rawGrantsRef.current = [];
        rawAllGrantsRef.current = [];
        setMyDocs([]);
        setActiveGrantsByDocId(new Map());
        setGrantsHasMore(false);
        setIsLoadingGrants(false);
        return;
      }
      const controller = new AbortController();
      grantsAbortRef.current = controller;
      const seq = ++grantsSeqRef.current;

      setIsLoadingGrants(true);
      if (!options?.silent) {
        setErrorMessageState(null);
      }

      try {
        const res = await apiClient<PagedGrantsResponse>(
          `/documents/my-grants?page=${grantsPage}&pageSize=${READER_PAGE_SIZE}`,
          { signal: controller.signal },
        );
        if (grantsSeqRef.current !== seq || controller.signal.aborted) return;

        const raw = res.data || [];
        const hasMore = Boolean(res.hasMore);
        let allRaw = raw;
        if (grantsPage > 1 || hasMore) {
          try {
            allRaw = await fetchBoundedActiveGrantsLookup(controller.signal);
          } catch (lookupErr) {
            if (isAbortError(lookupErr) || controller.signal.aborted) return;
          }
        }
        if (grantsSeqRef.current !== seq || controller.signal.aborted) return;

        rawGrantsRef.current = raw;
        rawAllGrantsRef.current = allRaw;
        const nowMs = Date.now();
        setMyDocs(mergeActiveReaderGrants(raw, nowMs, allRaw));
        setActiveGrantsByDocId(buildActiveGrantsByDocId(allRaw, nowMs));
        setGrantsHasMore(hasMore);
      } catch (err) {
        if (isAbortError(err) || controller.signal.aborted || grantsSeqRef.current !== seq) {
          return;
        }
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError
              ? err.message
              : 'Không thể tải danh sách tài liệu được cấp quyền.',
          );
        }
      } finally {
        if (grantsSeqRef.current === seq) {
          setIsLoadingGrants(false);
        }
      }
    },
    [canViewDocument, grantsPage, fetchBoundedActiveGrantsLookup, setErrorMessage],
  );

  const loadMyRequests = useCallback(
    async (options?: { silent?: boolean }) => {
      requestsAbortRef.current?.abort();
      if (!canViewOwnRequests) {
        setMyRequests([]);
        setRequestsTotal(0);
        setPendingRequestDocIds(new Set());
        setIsLoadingRequests(false);
        return;
      }
      const controller = new AbortController();
      requestsAbortRef.current = controller;
      const seq = ++requestsSeqRef.current;

      setIsLoadingRequests(true);
      if (!options?.silent) {
        setErrorMessageState(null);
      }

      try {
        const res = await apiClient<PagedRequestsResponse>(
          buildRequestsEndpoint(requestsPage, requestStatusFilter),
          { signal: controller.signal },
        );
        if (requestsSeqRef.current !== seq || controller.signal.aborted) return;

        const rows = res.data || [];
        const total = typeof res.total === 'number' ? res.total : rows.length;
        const maxPage = Math.max(1, Math.ceil(total / READER_PAGE_SIZE));
        if (requestsPage > maxPage || (requestsPage > 1 && rows.length === 0)) {
          setRequestsPage(Math.min(maxPage, requestsPage - 1));
          return;
        }
        setMyRequests(rows);
        setRequestsTotal(total);

        const pageCoversAllPending =
          (requestStatusFilter === 'ALL' || requestStatusFilter === 'PENDING') &&
          requestsPage === 1 &&
          total <= rows.length;
        if (pageCoversAllPending) {
          setPendingRequestDocIds(extractPendingRequestDocIds(rows));
        } else {
          try {
            const pendingIds = await fetchBoundedPendingRequestDocIds(controller.signal);
            if (requestsSeqRef.current === seq && !controller.signal.aborted) {
              setPendingRequestDocIds(pendingIds);
            }
          } catch (lookupErr) {
            if (isAbortError(lookupErr) || controller.signal.aborted) return;
          }
        }
      } catch (err) {
        if (isAbortError(err) || controller.signal.aborted || requestsSeqRef.current !== seq) {
          return;
        }
        if (!options?.silent) {
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải lịch sử yêu cầu truy cập.',
          );
        }
      } finally {
        if (requestsSeqRef.current === seq) {
          setIsLoadingRequests(false);
        }
      }
    },
    [
      canViewOwnRequests,
      requestsPage,
      requestStatusFilter,
      buildRequestsEndpoint,
      fetchBoundedPendingRequestDocIds,
      setErrorMessage,
    ],
  );

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      await Promise.resolve();
      if (!cancelled) void loadCatalog();
    };
    void run();
    return () => {
      cancelled = true;
      catalogAbortRef.current?.abort();
    };
  }, [loadCatalog]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      await Promise.resolve();
      if (!cancelled) void loadGrantedDocs();
    };
    void run();
    return () => {
      cancelled = true;
      grantsAbortRef.current?.abort();
    };
  }, [loadGrantedDocs]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      await Promise.resolve();
      if (!cancelled) void loadMyRequests();
    };
    void run();
    return () => {
      cancelled = true;
      requestsAbortRef.current?.abort();
    };
  }, [loadMyRequests]);

  const refreshData = useCallback(async () => {
    setErrorMessageState(null);
    setMessageState(null);
    await Promise.all([loadCatalog(), loadGrantedDocs(), loadMyRequests()]);
  }, [loadCatalog, loadGrantedDocs, loadMyRequests]);

  useEffect(() => {
    const timer = setInterval(() => {
      const nowMs = Date.now();
      if (rawGrantsRef.current.length > 0) {
        const merged = mergeActiveReaderGrants(
          rawGrantsRef.current,
          nowMs,
          rawAllGrantsRef.current,
        );
        const nextSig = buildGrantedDocsSignature(merged);
        setMyDocs((prev) => (buildGrantedDocsSignature(prev) === nextSig ? prev : merged));
      }
      if (rawAllGrantsRef.current.length > 0) {
        const nextMap = buildActiveGrantsByDocId(rawAllGrantsRef.current, nowMs);
        const nextMapSig = buildGrantedMapSignature(nextMap);
        setActiveGrantsByDocId((prev) =>
          buildGrantedMapSignature(prev) === nextMapSig ? prev : nextMap,
        );
      }
    }, 60_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    let syncTimer: ReturnType<typeof setTimeout> | null = null;
    const scheduleSync = () => {
      if (syncTimer) clearTimeout(syncTimer);
      syncTimer = setTimeout(() => {
        syncTimer = null;
        void loadGrantedDocs({ silent: true });
        void loadMyRequests({ silent: true });
      }, 150);
    };

    const unsubRequests = subscribeRealtimeEvent('ACCESS_REQUEST_UPDATED', scheduleSync);
    const unsubGrants = subscribeRealtimeEvent('ACCESS_GRANT_UPDATED', scheduleSync);

    return () => {
      unsubRequests();
      unsubGrants();
      if (syncTimer) clearTimeout(syncTimer);
    };
  }, [loadGrantedDocs, loadMyRequests]);

  const requestActions = useReaderRequestActions({
    myRequests,
    setMyRequests,
    requestsTotal,
    setRequestsTotal,
    requestsPage,
    setRequestsPage,
    requestStatusFilter,
    pageSize: READER_PAGE_SIZE,
    pendingRequestDocIds,
    setPendingRequestDocIds,
    setMessage,
    setErrorMessage,
  });

  const isLoading = isLoadingCatalog || isLoadingGrants || isLoadingRequests;

  return {
    discoverDocs,
    discoverPage,
    setDiscoverPage,
    discoverHasMore,
    isLoadingCatalog,
    myDocs,
    activeGrantsByDocId,
    grantsPage,
    setGrantsPage,
    grantsHasMore,
    isLoadingGrants,
    myRequests,
    pendingRequestDocIds,
    requestsPage,
    setRequestsPage,
    requestsTotal,
    requestsHasMore: requestsPage * READER_PAGE_SIZE < requestsTotal,
    isLoadingRequests,
    requestStatusFilter,
    setRequestStatusFilter: handleRequestStatusFilterChange,
    searchQuery,
    setSearchQuery: handleSearchChange,
    selectedClassification,
    setSelectedClassification: handleClassificationChange,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    refreshData,
    ...requestActions,
  };
}
