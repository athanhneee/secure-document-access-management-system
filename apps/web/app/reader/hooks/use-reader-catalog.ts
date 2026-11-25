'use client';

import { useState, useEffect, useCallback, useRef, type FormEvent } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { formatPermissionActionLabel } from '@/lib/ui-labels';
import {
  buildRequestWindowIso,
  isActiveReaderGrant,
  mapReaderDocumentDto,
  mapReaderGrantDto,
  validateCustomRequestWindow,
} from '../helpers';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  MyRequestItem,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from '../types';

const READER_PAGE_SIZE = 20;

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

/**
 * Thuật toán: Tải Danh Mục Người Đọc Phân Trang Theo Quyền Hạt Mịn, Tìm Kiếm Server-Side & Hủy Lạc Quan Có Hoàn Tác (`useReaderCatalog`)
 * Mục đích:
 *   - Chỉ gọi các điểm cuối nằm trong tập quyền thực tế (`DOCUMENT:DISCOVER`, `DOCUMENT:VIEW`, `ACCESS_REQUEST:VIEW_OWN`) tránh lỗi `403` giả (`V-18`).
 *   - Hỗ trợ phân trang đầy đủ (`page`, `hasMore`, `total`), tìm kiếm lai FTS/Trigram phía máy chủ kèm debounce 250ms (`V-37`, `V-38`), lọc tự động grant hết hạn theo chu kỳ 60s (`V-43`), và thông báo rõ lỗi khi bất kỳ nguồn nào thất bại (`V-41`).
 *   - Đảm bảo banner thành công/lỗi không xếp chồng (`V-44`), reset biểu mẫu mỗi lần mở modal (`V-40`) và hủy yêu cầu lạc quan thực sự kèm hoàn tác ảnh chụp (`V-55`).
 */
export function useReaderCatalog() {
  const { hasPermission } = useAuth();
  const canDiscover = hasPermission('DOCUMENT:DISCOVER');
  const canViewDocument = hasPermission('DOCUMENT:VIEW');
  const canViewOwnRequests = hasPermission('ACCESS_REQUEST:VIEW_OWN');

  const [discoverDocs, setDiscoverDocs] = useState<DiscoverableDoc[]>([]);
  const [discoverPage, setDiscoverPage] = useState(1);
  const [discoverHasMore, setDiscoverHasMore] = useState(false);

  const [myDocs, setMyDocs] = useState<MyGrantedDoc[]>([]);
  const [grantsPage, setGrantsPage] = useState(1);
  const [grantsHasMore, setGrantsHasMore] = useState(false);

  const [myRequests, setMyRequests] = useState<MyRequestItem[]>([]);
  const [requestsPage, setRequestsPage] = useState(1);
  const [requestsTotal, setRequestsTotal] = useState(0);
  const [requestStatusFilter, setRequestStatusFilter] = useState<string>('ALL');

  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessageState] = useState<string | null>(null);
  const [errorMessage, setErrorMessageState] = useState<string | null>(null);

  const [requestModalOpen, setRequestModalOpen] = useState(false);
  const [targetDoc, setTargetDoc] = useState<DiscoverableDoc | null>(null);
  const [requestedAction, setRequestedAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [justification, setJustification] = useState('');
  const [requestDurationDays, setRequestDurationDays] = useState(7);
  const [isCustomDuration, setIsCustomDuration] = useState(false);
  const [customRequestedFrom, setCustomRequestedFrom] = useState('');
  const [customRequestedUntil, setCustomRequestedUntil] = useState('');
  const [isSubmittingRequest, setIsSubmittingRequest] = useState(false);

  const [cancellingRequestId, setCancellingRequestId] = useState<string | null>(null);
  const [pendingCancelRequestId, setPendingCancelRequestId] = useState<string | null>(null);
  const rawGrantsRef = useRef<ReaderGrantApiDto[]>([]);
  const loadSeqRef = useRef(0);

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

  const refreshData = useCallback(async () => {
    const seq = ++loadSeqRef.current;
    setIsLoading(true);
    setErrorMessageState(null);
    setMessageState(null);

    try {
      const [docsResult, myGrantsResult, requestsResult] = await Promise.allSettled([
        canDiscover
          ? apiClient<PagedDocsResponse>(
              buildDiscoverEndpoint(discoverPage, debouncedSearch, selectedClassification),
            )
          : Promise.resolve(null),
        canViewDocument
          ? apiClient<PagedGrantsResponse>(
              `/documents/my-grants?page=${grantsPage}&pageSize=${READER_PAGE_SIZE}`,
            )
          : Promise.resolve(null),
        canViewOwnRequests
          ? apiClient<PagedRequestsResponse>(
              buildRequestsEndpoint(requestsPage, requestStatusFilter),
            )
          : Promise.resolve(null),
      ]);

      if (loadSeqRef.current !== seq) return;

      const failedSections: string[] = [];

      if (docsResult.status === 'fulfilled') {
        if (docsResult.value) {
          setDiscoverDocs((docsResult.value.data || []).map(mapReaderDocumentDto));
          setDiscoverHasMore(Boolean(docsResult.value.hasMore));
        } else {
          setDiscoverDocs([]);
          setDiscoverHasMore(false);
        }
      } else {
        failedSections.push('danh mục tài liệu');
      }

      if (myGrantsResult.status === 'fulfilled') {
        if (myGrantsResult.value) {
          const raw = myGrantsResult.value.data || [];
          rawGrantsRef.current = raw;
          const nowMs = Date.now();
          setMyDocs(
            raw
              .filter((g) => isActiveReaderGrant(g, nowMs))
              .map((g, idx) => mapReaderGrantDto(g, idx))
              .filter((g) => Boolean(g.documentId)),
          );
          setGrantsHasMore(Boolean(myGrantsResult.value.hasMore));
        } else {
          rawGrantsRef.current = [];
          setMyDocs([]);
          setGrantsHasMore(false);
        }
      } else {
        failedSections.push('tài liệu được cấp quyền');
      }

      if (requestsResult.status === 'fulfilled') {
        if (requestsResult.value) {
          const rows = requestsResult.value.data || [];
          setMyRequests(rows);
          setRequestsTotal(
            typeof requestsResult.value.total === 'number'
              ? requestsResult.value.total
              : rows.length,
          );
        } else {
          setMyRequests([]);
          setRequestsTotal(0);
        }
      } else {
        failedSections.push('yêu cầu truy cập');
      }

      if (failedSections.length > 0) {
        setErrorMessageState(
          `Không thể tải ${failedSections.join(', ')}. Vui lòng nhấn Làm mới để thử lại.`,
        );
      }
    } catch (err) {
      if (loadSeqRef.current !== seq) return;
      setErrorMessageState(
        err instanceof ApiError ? err.message : 'Không thể tải dữ liệu danh mục.',
      );
    } finally {
      if (loadSeqRef.current === seq) {
        setIsLoading(false);
      }
    }
  }, [
    canDiscover,
    canViewDocument,
    canViewOwnRequests,
    discoverPage,
    debouncedSearch,
    selectedClassification,
    grantsPage,
    requestsPage,
    requestStatusFilter,
    buildDiscoverEndpoint,
    buildRequestsEndpoint,
  ]);

  const refreshGrantsAndRequestsSilently = useCallback(async () => {
    const [myGrantsResult, requestsResult] = await Promise.allSettled([
      canViewDocument
        ? apiClient<PagedGrantsResponse>(
            `/documents/my-grants?page=${grantsPage}&pageSize=${READER_PAGE_SIZE}`,
          )
        : Promise.resolve(null),
      canViewOwnRequests
        ? apiClient<PagedRequestsResponse>(buildRequestsEndpoint(requestsPage, requestStatusFilter))
        : Promise.resolve(null),
    ]);

    if (myGrantsResult.status === 'fulfilled' && myGrantsResult.value) {
      const raw = myGrantsResult.value.data || [];
      rawGrantsRef.current = raw;
      const nowMs = Date.now();
      setMyDocs(
        raw
          .filter((g) => isActiveReaderGrant(g, nowMs))
          .map((g, idx) => mapReaderGrantDto(g, idx))
          .filter((g) => Boolean(g.documentId)),
      );
      setGrantsHasMore(Boolean(myGrantsResult.value.hasMore));
    }

    if (requestsResult.status === 'fulfilled' && requestsResult.value) {
      const rows = requestsResult.value.data || [];
      setMyRequests(rows);
      setRequestsTotal(
        typeof requestsResult.value.total === 'number' ? requestsResult.value.total : rows.length,
      );
    }
  }, [
    canViewDocument,
    canViewOwnRequests,
    grantsPage,
    requestsPage,
    requestStatusFilter,
    buildRequestsEndpoint,
  ]);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshData();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refreshData]);

  // Thuật toán: Tự động loại bỏ grant vừa hết hạn theo đồng hồ trình duyệt mỗi 60 giây (V-43).
  useEffect(() => {
    const timer = setInterval(() => {
      if (rawGrantsRef.current.length === 0) return;
      const nowMs = Date.now();
      const filtered = rawGrantsRef.current
        .filter((g) => isActiveReaderGrant(g, nowMs))
        .map((g, idx) => mapReaderGrantDto(g, idx))
        .filter((g) => Boolean(g.documentId));
      setMyDocs((prev) => (prev.length === filtered.length ? prev : filtered));
    }, 60_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    let syncTimer: ReturnType<typeof setTimeout> | null = null;
    const scheduleSync = () => {
      if (syncTimer) clearTimeout(syncTimer);
      syncTimer = setTimeout(() => {
        syncTimer = null;
        void refreshGrantsAndRequestsSilently();
      }, 150);
    };

    const unsubRequests = subscribeRealtimeEvent('ACCESS_REQUEST_UPDATED', scheduleSync);
    const unsubGrants = subscribeRealtimeEvent('ACCESS_GRANT_UPDATED', scheduleSync);

    return () => {
      unsubRequests();
      unsubGrants();
      if (syncTimer) clearTimeout(syncTimer);
    };
  }, [refreshGrantsAndRequestsSilently]);

  function openRequestModal(doc: DiscoverableDoc, initialAction: 'VIEW' | 'DOWNLOAD' = 'VIEW') {
    setErrorMessageState(null);
    setTargetDoc(doc);
    setRequestedAction(initialAction === 'DOWNLOAD' && doc.allowDownload ? 'DOWNLOAD' : 'VIEW');
    setJustification('');
    // Reset hoàn toàn cấu hình thời hạn của lần mở trước (V-40)
    setRequestDurationDays(7);
    setIsCustomDuration(false);
    setCustomRequestedFrom('');
    setCustomRequestedUntil('');
    setRequestModalOpen(true);
  }

  async function handleSubmitRequest(e: FormEvent) {
    e.preventDefault();
    if (!targetDoc) return;

    const trimmedReason = justification.trim();
    if (trimmedReason.length < 10) {
      setErrorMessage('Lý do đề xuất truy cập phải có tối thiểu 10 ký tự.');
      return;
    }
    if (trimmedReason.length > 1000) {
      setErrorMessage('Lý do đề xuất truy cập không được vượt quá 1000 ký tự.');
      return;
    }

    const customWindowError = validateCustomRequestWindow(
      isCustomDuration,
      customRequestedFrom,
      customRequestedUntil,
    );
    if (customWindowError) {
      setErrorMessage(customWindowError);
      return;
    }

    setIsSubmittingRequest(true);
    setErrorMessageState(null);

    try {
      const { fromIso, untilIso } = buildRequestWindowIso(
        isCustomDuration,
        customRequestedFrom,
        customRequestedUntil,
        requestDurationDays,
      );

      const created = await apiClient<MyRequestItem>('/access-requests', {
        method: 'POST',
        body: JSON.stringify({
          documentId: targetDoc.id,
          requestedAction,
          reason: trimmedReason,
          requestedFrom: fromIso,
          requestedUntil: untilIso,
        }),
      });

      setMessage(
        `Đã gửi yêu cầu quyền "${formatPermissionActionLabel(requestedAction)}" cho tài liệu "${targetDoc.title}" đến chủ sở hữu để phê duyệt.`,
      );
      setRequestModalOpen(false);
      setTargetDoc(null);
      setJustification('');
      setRequestDurationDays(7);
      setIsCustomDuration(false);
      setCustomRequestedFrom('');
      setCustomRequestedUntil('');
      setMyRequests((prev) => [created, ...prev].slice(0, READER_PAGE_SIZE));
      setRequestsTotal((prev) => prev + 1);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message
          : err instanceof Error && err.message
            ? err.message
            : 'Không thể gửi yêu cầu cấp quyền.',
      );
    } finally {
      setIsSubmittingRequest(false);
    }
  }

  // CONFLICT-RESOLVED: Cập nhật lạc quan thực sự dưới 16ms kèm hoàn tác ảnh chụp khi lỗi và luôn đóng hộp thoại xác nhận (V-46, V-55).
  async function handleCancelRequest(explicitId?: string) {
    const requestId = explicitId ?? pendingCancelRequestId;
    if (!requestId) {
      return;
    }
    const previousRequests = myRequests;
    setPendingCancelRequestId(null);
    setCancellingRequestId(requestId);
    setErrorMessageState(null);
    setMyRequests((prev) => applyOptimisticStatusById(prev, requestId, 'CANCELLED'));

    try {
      await apiClient(`/access-requests/${requestId}/cancel`, {
        method: 'POST',
      });
      setMessage('Đã hủy yêu cầu truy cập thành công.');
    } catch (err) {
      setMyRequests(previousRequests);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể hủy yêu cầu truy cập.'
          : 'Không thể hủy yêu cầu truy cập.',
      );
    } finally {
      setCancellingRequestId(null);
    }
  }

  const pendingCancelRequest = myRequests.find((r) => r.id === pendingCancelRequestId) ?? null;

  return {
    discoverDocs,
    discoverPage,
    setDiscoverPage,
    discoverHasMore,
    myDocs,
    grantsPage,
    setGrantsPage,
    grantsHasMore,
    myRequests,
    requestsPage,
    setRequestsPage,
    requestsTotal,
    requestsHasMore: requestsPage * READER_PAGE_SIZE < requestsTotal,
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
    requestModalOpen,
    setRequestModalOpen,
    targetDoc,
    openRequestModal,
    requestedAction,
    setRequestedAction,
    justification,
    setJustification,
    requestDurationDays,
    setRequestDurationDays,
    isCustomDuration,
    setIsCustomDuration,
    customRequestedFrom,
    setCustomRequestedFrom,
    customRequestedUntil,
    setCustomRequestedUntil,
    isSubmittingRequest,
    handleSubmitRequest,
    cancellingRequestId,
    pendingCancelRequestId,
    pendingCancelRequest,
    setPendingCancelRequestId,
    handleCancelRequest,
  };
}
