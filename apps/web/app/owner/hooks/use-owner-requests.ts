'use client';

import { useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { DEFAULT_GRANT_MAX_DURATION_DAYS, computeEffectiveAccessCeiling } from '@sda/contracts';
import { apiClient, ApiError } from '@/lib/api-client';
import { removeOptimisticById } from '@/lib/optimistic-state';
import { formatPermissionActionLabel, formatSafeDateVi } from '@/lib/ui-labels';
import {
  calculateRequestedDays,
  expandGrantPermissions,
  inferAllowDownloadFromClassificationCode,
} from '../helpers';
import type { AccessRequestItem, DocumentItem } from '../types';

interface UseOwnerRequestsParams {
  documents?: DocumentItem[] | undefined;
  requestsPage?: number | undefined;
  requestsCountOnPage?: number | undefined;
  onLoadRequestsPage?: ((page: number) => Promise<boolean> | void) | undefined;
  setRequests: Dispatch<SetStateAction<AccessRequestItem[]>>;
  setRequestsTotal?: Dispatch<SetStateAction<number>> | undefined;
  onRequestApproved?: () => Promise<void>;
  setMessage: (msg: string | null) => void;
  setDialogError: (msg: string | null) => void;
}

export interface RequestApprovalDocumentMeta {
  retentionUntil: string | null;
  defaultViewDays: number | null;
  allowDownload: boolean;
}

/**
 * Thuật toán: Phán Quyết Phê Duyệt / Từ Chối Ràng Buộc Trần Lưu Trữ & Ghi Chú Lý Do Từ Chối (`useOwnerRequests`, BUG-102)
 * Mục đích:
 *   - Chặn đóng hộp thoại khi đang gửi quyết định duyệt/từ chối (`isApproving` / `isRejecting`).
 *   - Thay thế hộp thoại xác nhận cứng bằng biểu mẫu nhập `decisionNote` (tối đa 1000 ký tự) khi từ chối yêu cầu.
 */
export function useOwnerRequests({
  documents = [],
  requestsPage = 1,
  requestsCountOnPage = 0,
  onLoadRequestsPage,
  setRequests,
  setRequestsTotal,
  onRequestApproved,
  setMessage,
  setDialogError,
}: UseOwnerRequestsParams) {
  const [approveOpen, setApproveOpenState] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<AccessRequestItem | null>(null);
  const [grantValidDays, setGrantValidDays] = useState(7);
  const [grantValidUntilOverride, setGrantValidUntilOverride] = useState<string | null>(null);
  const [grantAction, setGrantAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [approveNote, setApproveNote] = useState('');
  const [isApproving, setIsApproving] = useState(false);

  const [rejectOpen, setRejectOpenState] = useState(false);
  const [requestToReject, setRequestToReject] = useState<AccessRequestItem | null>(null);
  const [rejectDecisionNote, setRejectDecisionNote] = useState('');
  const [isRejecting, setIsRejecting] = useState(false);

  function setApproveOpen(nextOpen: boolean) {
    if (!nextOpen && isApproving) return;
    if (!nextOpen) setDialogError(null);
    setApproveOpenState(nextOpen);
  }

  function setRejectOpen(nextOpen: boolean) {
    if (!nextOpen && isRejecting) return;
    if (!nextOpen) {
      setDialogError(null);
      setRequestToReject(null);
      setRejectDecisionNote('');
    }
    setRejectOpenState(nextOpen);
  }

  function resolveDocMeta(req: AccessRequestItem | null): RequestApprovalDocumentMeta {
    if (!req) {
      return { retentionUntil: null, defaultViewDays: null, allowDownload: false };
    }
    const matchedDoc = documents.find((d) => d.id === req.documentId);
    const clsCode = req.documentClassificationCode ?? matchedDoc?.classificationCode ?? null;
    return {
      retentionUntil: req.documentRetentionUntil ?? matchedDoc?.retentionUntil ?? null,
      defaultViewDays: req.documentDefaultViewDays ?? matchedDoc?.defaultViewDays ?? null,
      allowDownload:
        req.documentAllowDownload ??
        matchedDoc?.allowDownload ??
        inferAllowDownloadFromClassificationCode(clsCode),
    };
  }

  function openApproveModal(req: AccessRequestItem) {
    setDialogError(null);
    const meta = resolveDocMeta(req);
    const now = new Date();
    const ceiling = computeEffectiveAccessCeiling({
      fromDate: now,
      maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
      retentionUntil: meta.retentionUntil,
      timezoneMode: 'safe-local',
    });

    const requestedDays = calculateRequestedDays(
      req.requestedFrom,
      req.requestedUntil,
      DEFAULT_GRANT_MAX_DURATION_DAYS,
    );
    const existingGrant = req.existingActiveGrant;
    const existingMs = existingGrant ? Date.parse(existingGrant.validUntil) : Number.NaN;
    const reqUntilMs = req.requestedUntil ? Date.parse(req.requestedUntil) : Number.NaN;
    const hasUsableExisting =
      !Number.isNaN(existingMs) &&
      existingMs > now.getTime() + 60_000 &&
      existingMs <= ceiling.maxUntil.getTime();
    const isDownloadUpgradeOnExisting =
      Boolean(existingGrant) &&
      req.requestedAction === 'DOWNLOAD' &&
      !existingGrant?.permissions.includes('DOWNLOAD');
    const requestedMatchesExisting =
      hasUsableExisting &&
      !Number.isNaN(reqUntilMs) &&
      Math.abs(reqUntilMs - existingMs) <= 120_000;

    setSelectedRequest(req);
    setApproveNote('');
    setGrantAction(req.requestedAction === 'DOWNLOAD' && meta.allowDownload ? 'DOWNLOAD' : 'VIEW');

    if (ceiling.isRetentionExpired) {
      setGrantValidDays(1);
      setGrantValidUntilOverride(null);
    } else if (hasUsableExisting && (requestedMatchesExisting || isDownloadUpgradeOnExisting)) {
      setGrantValidDays(Math.max(1, Math.round((existingMs - now.getTime()) / 86_400_000)));
      setGrantValidUntilOverride(new Date(existingMs).toISOString());
    } else if (ceiling.maxWholeDays === 0) {
      setGrantValidDays(1);
      setGrantValidUntilOverride(ceiling.maxUntil.toISOString());
    } else {
      const clampedDays = Math.min(Math.max(1, requestedDays), ceiling.maxWholeDays);
      setGrantValidDays(clampedDays);
      setGrantValidUntilOverride(null);
    }
    setApproveOpenState(true);
  }

  function openRejectModal(req: AccessRequestItem) {
    setDialogError(null);
    setRequestToReject(req);
    setRejectDecisionNote('');
    setRejectOpenState(true);
  }

  function handleSelectValidDays(days: number) {
    setGrantValidUntilOverride(null);
    setGrantValidDays(days);
  }

  function handleSelectValidUntilOverride(untilIso: string | null) {
    setGrantValidUntilOverride(untilIso);
  }

  async function handleConfirmApprove() {
    if (!selectedRequest) return;
    const target = selectedRequest;
    const meta = resolveDocMeta(target);
    const actionSnapshot = grantAction === 'DOWNLOAD' && !meta.allowDownload ? 'VIEW' : grantAction;
    const daysSnapshot = grantValidDays;
    const untilOverrideSnapshot = grantValidUntilOverride;
    const trimmedNote = approveNote.trim();
    if (trimmedNote.length > 1000) {
      setDialogError('Ghi chú phê duyệt không được vượt quá 1000 ký tự.');
      return;
    }

    setIsApproving(true);
    setDialogError(null);

    try {
      const grantedPermissions = expandGrantPermissions(actionSnapshot);
      const bodyPayload: {
        decision: 'APPROVED';
        permissions: Array<'VIEW' | 'DOWNLOAD'>;
        validDays?: number;
        validUntil?: string;
        decisionNote?: string;
      } = {
        decision: 'APPROVED',
        permissions: grantedPermissions,
      };
      if (untilOverrideSnapshot) {
        bodyPayload.validUntil = untilOverrideSnapshot;
      } else {
        bodyPayload.validDays = daysSnapshot;
      }
      if (trimmedNote) {
        bodyPayload.decisionNote = trimmedNote;
      }

      await apiClient(`/access-requests/${target.id}/decide`, {
        method: 'POST',
        body: JSON.stringify(bodyPayload),
      });
      setIsApproving(false);
      setApproveOpenState(false);
      setSelectedRequest(null);
      setGrantValidUntilOverride(null);
      setApproveNote('');
      setRequests((prev) => removeOptimisticById(prev, target.id));
      setRequestsTotal?.((prev) => Math.max(0, prev - 1));
      if (requestsPage > 1 && requestsCountOnPage <= 1) {
        void onLoadRequestsPage?.(requestsPage - 1);
      }
      const durationSummary = untilOverrideSnapshot
        ? `đến ${formatSafeDateVi(untilOverrideSnapshot, { includeTime: true })}`
        : `trong ${daysSnapshot} ngày`;
      setMessage(
        `Đã phê duyệt yêu cầu và cấp quyền "${formatPermissionActionLabel(actionSnapshot)}" cho ${target.requestorName} ${durationSummary}.`,
      );
      void onRequestApproved?.();
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể phê duyệt yêu cầu.'
          : 'Đã xảy ra lỗi khi cấp quyền truy cập.',
      );
      setIsApproving(false);
    }
  }

  async function handleConfirmReject(e: FormEvent) {
    e.preventDefault();
    if (!requestToReject) return;
    const trimmedNote = rejectDecisionNote.trim();
    if (!trimmedNote) {
      setDialogError('Vui lòng nhập lý do từ chối yêu cầu truy cập để thông báo cho người gửi.');
      return;
    }
    if (trimmedNote.length > 1000) {
      setDialogError('Lý do từ chối không được vượt quá 1000 ký tự.');
      return;
    }

    const target = requestToReject;
    setIsRejecting(true);
    setDialogError(null);
    try {
      await apiClient(`/access-requests/${target.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'REJECTED',
          decisionNote: trimmedNote,
        }),
      });
      setIsRejecting(false);
      setRejectOpenState(false);
      setRequestToReject(null);
      setRejectDecisionNote('');
      setRequests((prev) => removeOptimisticById(prev, target.id));
      setRequestsTotal?.((prev) => Math.max(0, prev - 1));
      if (requestsPage > 1 && requestsCountOnPage <= 1) {
        void onLoadRequestsPage?.(requestsPage - 1);
      }
      setMessage(`Đã từ chối yêu cầu truy cập của ${target.requestorName}.`);
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể từ chối yêu cầu.'
          : 'Đã xảy ra lỗi khi từ chối yêu cầu.',
      );
      setIsRejecting(false);
    }
  }

  return {
    approveOpen,
    setApproveOpen,
    selectedRequest,
    selectedRequestDocMeta: resolveDocMeta(selectedRequest),
    grantValidDays,
    setGrantValidDays: handleSelectValidDays,
    grantValidUntilOverride,
    setGrantValidUntilOverride: handleSelectValidUntilOverride,
    grantAction,
    setGrantAction,
    approveNote,
    setApproveNote,
    isApproving,
    openApproveModal,
    handleConfirmApprove,
    rejectOpen,
    setRejectOpen,
    requestToReject,
    rejectDecisionNote,
    setRejectDecisionNote,
    isRejecting,
    openRejectModal,
    handleConfirmReject,
  };
}
