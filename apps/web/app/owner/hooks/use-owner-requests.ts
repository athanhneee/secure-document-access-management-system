'use client';

import { useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { calculateRequestedDays, expandGrantPermissions } from '../helpers';
import type { AccessRequestItem } from '../types';

interface UseOwnerRequestsParams {
  refreshData: () => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Phán quyết Phê duyệt / Từ chối Yêu cầu Truy cập (`useOwnerRequests`)
 * Khởi tạo khoảng ngày hiệu lực từ yêu cầu của người đọc và đảm bảo quyết định `APPROVED` cho `DOWNLOAD` luôn gửi kèm quyền nền `VIEW`.
 */
export function useOwnerRequests({
  refreshData,
  setMessage,
  setErrorMessage,
}: UseOwnerRequestsParams) {
  const [approveOpen, setApproveOpen] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<AccessRequestItem | null>(null);
  const [grantValidDays, setGrantValidDays] = useState(7);
  const [grantAction, setGrantAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [isApproving, setIsApproving] = useState(false);

  function openApproveModal(req: AccessRequestItem) {
    setSelectedRequest(req);
    setGrantAction(req.requestedAction);
    setGrantValidDays(calculateRequestedDays(req.requestedFrom, req.requestedUntil));
    setApproveOpen(true);
  }

  async function handleConfirmApprove() {
    if (!selectedRequest) return;
    setIsApproving(true);
    setErrorMessage(null);

    try {
      // CONFLICT-RESOLVED: Khi phê duyệt mức DOWNLOAD, gửi đầy đủ ['VIEW', 'DOWNLOAD'] để người nhận vừa xem trực tuyến vừa tải bản sao.
      const grantedPermissions = expandGrantPermissions(grantAction);
      await apiClient(`/access-requests/${selectedRequest.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'APPROVED',
          validDays: grantValidDays,
          permissions: grantedPermissions,
        }),
      });

      setMessage(
        `Đã phê duyệt yêu cầu và cấp quyền ${grantAction} tài liệu cho ${selectedRequest.requestorName} trong ${grantValidDays} ngày.`,
      );
      setApproveOpen(false);
      setSelectedRequest(null);
      await refreshData();
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể phê duyệt yêu cầu.'
          : 'Đã xảy ra lỗi khi tạo giấy phép truy cập.',
      );
    } finally {
      setIsApproving(false);
    }
  }

  async function handleRejectRequest(req: AccessRequestItem) {
    setErrorMessage(null);
    try {
      await apiClient(`/access-requests/${req.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'REJECTED',
          decisionNote: 'Chủ sở hữu từ chối cấp quyền truy cập.',
        }),
      });
      setMessage(`Đã từ chối yêu cầu truy cập của ${req.requestorName}.`);
      await refreshData();
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể từ chối yêu cầu.'
          : 'Đã xảy ra lỗi khi từ chối yêu cầu.',
      );
    }
  }

  return {
    approveOpen,
    setApproveOpen,
    selectedRequest,
    grantValidDays,
    setGrantValidDays,
    grantAction,
    setGrantAction,
    isApproving,
    openApproveModal,
    handleConfirmApprove,
    handleRejectRequest,
  };
}
