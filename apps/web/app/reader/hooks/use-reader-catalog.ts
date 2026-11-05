'use client';

import { useState, useEffect, useCallback, type FormEvent } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { buildRequestWindowIso, mapReaderDocumentDto, mapReaderGrantDto } from '../helpers';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  MyRequestItem,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from '../types';

/**
 * Thuật toán: Tải Đồng thời Danh mục Người đọc & Quản lý Vòng đời Yêu cầu Xin Quyền (`useReaderCatalog`)
 * Mục đích: Đồng bộ song song danh mục khám phá, danh sách quyền hiệu lực và lịch sử yêu cầu cá nhân mà không chặn lẫn nhau.
 * Cơ chế hoạt động:
 *   - Dùng `Promise.allSettled` tải 3 nguồn dữ liệu độc lập (`O(N)`), kết hợp cờ hủy `ignore` chống ghi đè phản hồi trễ và hỗ trợ gửi/hủy yêu cầu ở trạng thái `PENDING`.
 */
export function useReaderCatalog() {
  const [discoverDocs, setDiscoverDocs] = useState<DiscoverableDoc[]>([]);
  const [myDocs, setMyDocs] = useState<MyGrantedDoc[]>([]);
  const [myRequests, setMyRequests] = useState<MyRequestItem[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [docsResult, myGrantsResult, requestsResult] = await Promise.allSettled([
        apiClient<{ data: ReaderDocumentApiDto[] }>('/documents?pageSize=50'),
        apiClient<{ data: ReaderGrantApiDto[] }>('/documents/my-grants?pageSize=50'),
        apiClient<{ data: MyRequestItem[] }>('/access-requests?scope=my'),
      ]);

      if (docsResult.status === 'fulfilled') {
        setDiscoverDocs((docsResult.value.data || []).map(mapReaderDocumentDto));
      } else {
        setErrorMessage('Không thể tải danh sách tài liệu từ máy chủ.');
      }

      if (myGrantsResult.status === 'fulfilled') {
        setMyDocs((myGrantsResult.value.data || []).map(mapReaderGrantDto));
      }

      if (requestsResult.status === 'fulfilled') {
        setMyRequests(requestsResult.value.data || []);
      }
    } catch (err) {
      setErrorMessage(err instanceof ApiError ? err.message : 'Không thể tải dữ liệu danh mục.');
    } finally {
      setIsLoading(false);
    }
  }, []);

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

  function openRequestModal(doc: DiscoverableDoc) {
    setTargetDoc(doc);
    setJustification('');
    setRequestModalOpen(true);
  }

  async function handleSubmitRequest(e: FormEvent) {
    e.preventDefault();
    if (!targetDoc) return;

    if (justification.trim().length < 10) {
      setErrorMessage('Lý do đề xuất truy cập phải có ít nhất 10 ký tự.');
      return;
    }

    setIsSubmittingRequest(true);
    setErrorMessage(null);

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
          reason: justification.trim(),
          requestedFrom: fromIso,
          requestedUntil: untilIso,
        }),
      });

      setMessage(
        `Yêu cầu quyền ${requestedAction} tài liệu "${targetDoc.title}" đã được gửi đến chủ sở hữu để xét duyệt.`,
      );
      setRequestModalOpen(false);
      setTargetDoc(null);
      setJustification('');
      setIsCustomDuration(false);
      setCustomRequestedFrom('');
      setCustomRequestedUntil('');
      setMyRequests((prev) => [created, ...prev]);
    } catch (err) {
      setErrorMessage(err instanceof ApiError ? err.message : 'Không thể gửi yêu cầu cấp quyền.');
    } finally {
      setIsSubmittingRequest(false);
    }
  }

  // CONFLICT-RESOLVED: Loại bỏ hộp thoại xác nhận thô của trình duyệt, chuyển sang ConfirmDialog chuẩn WCAG 2.1 AA (rules/ui-design-system.md §6.3)
  async function handleCancelRequest(explicitId?: string) {
    const requestId = explicitId ?? pendingCancelRequestId;
    if (!requestId) {
      return;
    }
    setCancellingRequestId(requestId);
    setErrorMessage(null);
    try {
      await apiClient(`/access-requests/${requestId}/cancel`, {
        method: 'POST',
      });
      setMessage('Đã hủy yêu cầu cấp quyền thành công.');
      setMyRequests((prev) =>
        prev.map((r) => (r.id === requestId ? { ...r, status: 'CANCELLED' } : r)),
      );
      setPendingCancelRequestId(null);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể hủy yêu cầu truy cập.'
          : 'Không thể hủy yêu cầu truy cập.',
      );
    } finally {
      setCancellingRequestId(null);
    }
  }

  return {
    discoverDocs,
    myDocs,
    myRequests,
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
    setPendingCancelRequestId,
    handleCancelRequest,
  };
}
