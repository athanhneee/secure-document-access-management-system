'use client';

import { useCallback, useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { DEFAULT_GRANT_MAX_DURATION_DAYS, buildAccessDurationPresets } from '@sda/contracts';
import { apiClient, ApiError } from '@/lib/api-client';
import { formatPermissionActionLabel } from '@/lib/ui-labels';
import {
  applyCancelledRequestToFilteredPage,
  applyCreatedRequestToFilteredPage,
  buildRequestWindowIso,
  validateCustomRequestWindow,
} from '../helpers';
import type { DiscoverableDoc, MyRequestItem } from '../types';

interface UseReaderRequestActionsParams {
  myRequests: MyRequestItem[];
  setMyRequests: Dispatch<SetStateAction<MyRequestItem[]>>;
  requestsTotal: number;
  setRequestsTotal: Dispatch<SetStateAction<number>>;
  requestsPage: number;
  setRequestsPage?: Dispatch<SetStateAction<number>> | undefined;
  requestStatusFilter: string;
  pageSize: number;
  pendingRequestDocIds: ReadonlySet<string>;
  setPendingRequestDocIds: Dispatch<SetStateAction<ReadonlySet<string>>>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Điều Phối Biểu Mẫu Gửi Yêu Cầu Truy Cập & Hủy Yêu Cầu Lạc Quan Có Hoàn Tác (`useReaderRequestActions`, BUG-102)
 * Mục đích:
 *   - Tách biệt lỗi hộp thoại (`dialogError`) khỏi banner lỗi nền (`errorMessage`) để lỗi không lặp đôi trong và ngoài modal, đồng thời tự động xóa sạch khi đóng hộp thoại.
 *   - Khóa cứng thao tác đóng `RequestAccessModal` (`Escape`, nhấp nền mờ, nút Hủy) khi `isSubmittingRequest === true` nhằm ngăn mất trạng thái gửi dở dang.
 *   - Cập nhật lạc quan danh sách yêu cầu và tập `pendingRequestDocIds` khi gửi mới hoặc hủy yêu cầu, hoàn tác nguyên trạng nếu API trả lỗi.
 */
export function useReaderRequestActions({
  myRequests,
  setMyRequests,
  requestsTotal,
  setRequestsTotal,
  requestsPage,
  setRequestsPage,
  requestStatusFilter,
  pageSize,
  pendingRequestDocIds,
  setPendingRequestDocIds,
  setMessage,
  setErrorMessage,
}: UseReaderRequestActionsParams) {
  const [requestModalOpen, setRequestModalOpenRaw] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [targetDoc, setTargetDoc] = useState<DiscoverableDoc | null>(null);
  const [requestedAction, setRequestedAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [justification, setJustification] = useState('');
  const [requestDurationDays, setRequestDurationDays] = useState(7);
  const [requestPresetKey, setRequestPresetKey] = useState<string>('DAYS:7');
  const [requestExplicitUntilIso, setRequestExplicitUntilIso] = useState<string | null>(null);
  const [requestExistingGrantUntil, setRequestExistingGrantUntil] = useState<string | null>(null);
  const [requestIntent, setRequestIntent] = useState<'NEW' | 'UPGRADE_DOWNLOAD' | 'RENEW'>('NEW');
  const [isCustomDuration, setIsCustomDuration] = useState(false);
  const [customRequestedFrom, setCustomRequestedFrom] = useState('');
  const [customRequestedUntil, setCustomRequestedUntil] = useState('');
  const [isSubmittingRequest, setIsSubmittingRequest] = useState(false);

  const [cancellingRequestId, setCancellingRequestId] = useState<string | null>(null);
  const [pendingCancelRequestId, setPendingCancelRequestId] = useState<string | null>(null);

  const resetRequestDraft = useCallback(() => {
    setTargetDoc(null);
    setJustification('');
    setRequestDurationDays(7);
    setRequestPresetKey('DAYS:7');
    setRequestExplicitUntilIso(null);
    setRequestExistingGrantUntil(null);
    setRequestIntent('NEW');
    setIsCustomDuration(false);
    setCustomRequestedFrom('');
    setCustomRequestedUntil('');
  }, []);

  const setRequestModalOpen = useCallback(
    (open: boolean) => {
      if (!open && isSubmittingRequest) {
        return;
      }
      setDialogError(null);
      setRequestModalOpenRaw(open);
      if (!open) {
        resetRequestDraft();
      }
    },
    [isSubmittingRequest, resetRequestDraft],
  );

  const openRequestModal = useCallback(
    (
      doc: DiscoverableDoc,
      initialAction: 'VIEW' | 'DOWNLOAD' = 'VIEW',
      options?: {
        existingGrantValidUntil?: string | null | undefined;
        intent?: 'NEW' | 'UPGRADE_DOWNLOAD' | 'RENEW' | undefined;
      },
    ) => {
      setDialogError(null);
      const intent = options?.intent ?? 'NEW';
      const existingGrantValidUntil = options?.existingGrantValidUntil ?? null;
      const plan = buildAccessDurationPresets({
        maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
        retentionUntil: doc.retentionUntil,
        defaultViewDays: doc.defaultViewDays,
        classificationCode: doc.classificationCode,
        existingGrantValidUntil,
        intent,
      });
      const defaultOpt =
        plan.options.find((o) => o.key === plan.defaultOptionKey) ?? plan.options[0];

      setTargetDoc(doc);
      setRequestedAction(initialAction === 'DOWNLOAD' && doc.allowDownload ? 'DOWNLOAD' : 'VIEW');
      setJustification('');
      setRequestIntent(intent);
      setRequestExistingGrantUntil(existingGrantValidUntil);
      setRequestPresetKey(defaultOpt?.key ?? '');
      setRequestDurationDays(defaultOpt?.days ?? Math.max(1, plan.recommendedDays || 1));
      setRequestExplicitUntilIso(defaultOpt?.untilIso ?? null);
      setIsCustomDuration(false);
      setCustomRequestedFrom('');
      setCustomRequestedUntil('');
      setRequestModalOpenRaw(true);
    },
    [],
  );

  async function handleSubmitRequest(e: FormEvent) {
    e.preventDefault();
    if (!targetDoc || isSubmittingRequest) return;

    const trimmedReason = justification.trim();
    if (trimmedReason.length < 10) {
      setDialogError('Lý do đề xuất truy cập phải có tối thiểu 10 ký tự.');
      return;
    }
    if (trimmedReason.length > 1000) {
      setDialogError('Lý do đề xuất truy cập không được vượt quá 1000 ký tự.');
      return;
    }

    const customWindowError = validateCustomRequestWindow(
      isCustomDuration,
      customRequestedFrom,
      customRequestedUntil,
      Date.now(),
      {
        maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
        retentionUntil: targetDoc.retentionUntil,
      },
    );
    if (customWindowError) {
      setDialogError(customWindowError);
      return;
    }

    setIsSubmittingRequest(true);
    setDialogError(null);

    try {
      const { fromIso, untilIso } = buildRequestWindowIso(
        isCustomDuration,
        customRequestedFrom,
        customRequestedUntil,
        requestDurationDays,
        {
          maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
          retentionUntil: targetDoc.retentionUntil,
          explicitUntilIso: !isCustomDuration ? requestExplicitUntilIso : null,
        },
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

      const submittedDocId = created.documentId || targetDoc.id;
      const submittedTitle = targetDoc.title;
      setPendingRequestDocIds((prev) => {
        const next = new Set(prev);
        next.add(submittedDocId);
        return next;
      });
      const createdWithDocId: MyRequestItem = {
        ...created,
        documentId: submittedDocId,
      };
      const pageUpdate = applyCreatedRequestToFilteredPage({
        currentRequests: myRequests,
        currentTotal: requestsTotal,
        created: createdWithDocId,
        statusFilter: requestStatusFilter,
        page: requestsPage,
        pageSize,
      });
      setMyRequests(pageUpdate.nextRequests);
      setRequestsTotal(pageUpdate.nextTotal);
      setDialogError(null);
      setRequestModalOpenRaw(false);
      resetRequestDraft();
      setMessage(
        `Đã gửi yêu cầu quyền "${formatPermissionActionLabel(requestedAction)}" cho tài liệu "${submittedTitle}" đến chủ sở hữu để phê duyệt.`,
      );
    } catch (err) {
      setDialogError(
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

  async function handleCancelRequest(explicitId?: string) {
    const requestId = explicitId ?? pendingCancelRequestId;
    if (!requestId || cancellingRequestId) {
      return;
    }
    const previousRequests = myRequests;
    const previousTotal = requestsTotal;
    const previousPendingDocIds = pendingRequestDocIds;
    const cancelledItem = myRequests.find((r) => r.id === requestId);
    const hasSiblingPendingForDoc = Boolean(
      cancelledItem?.documentId &&
      myRequests.some(
        (r) =>
          r.id !== requestId && r.status === 'PENDING' && r.documentId === cancelledItem.documentId,
      ),
    );

    setCancellingRequestId(requestId);
    setErrorMessage(null);

    if (cancelledItem?.documentId && !hasSiblingPendingForDoc) {
      const docIdToRemove = cancelledItem.documentId;
      setPendingRequestDocIds((prev) => {
        if (!prev.has(docIdToRemove)) return prev;
        const next = new Set(prev);
        next.delete(docIdToRemove);
        return next;
      });
    }

    const cancelledUpdate = applyCancelledRequestToFilteredPage({
      currentRequests: myRequests,
      currentTotal: requestsTotal,
      requestId,
      statusFilter: requestStatusFilter,
    });
    setMyRequests(cancelledUpdate.nextRequests);
    setRequestsTotal(cancelledUpdate.nextTotal);

    try {
      await apiClient(`/access-requests/${requestId}/cancel`, {
        method: 'POST',
      });
      setPendingCancelRequestId(null);
      if (requestsPage > 1 && cancelledUpdate.nextRequests.length === 0) {
        setRequestsPage?.(requestsPage - 1);
      }
      setMessage('Đã hủy yêu cầu truy cập thành công.');
    } catch (err) {
      setPendingCancelRequestId(null);
      setMyRequests(previousRequests);
      setRequestsTotal(previousTotal);
      setPendingRequestDocIds(previousPendingDocIds);
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
    dialogError,
    setDialogError,
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
    requestPresetKey,
    setRequestPresetKey,
    requestExplicitUntilIso,
    setRequestExplicitUntilIso,
    requestExistingGrantUntil,
    requestIntent,
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
