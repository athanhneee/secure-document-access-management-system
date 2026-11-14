'use client';

import { useState, type Dispatch, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { removeOptimisticById } from '@/lib/optimistic-state';
import { calculateRequestedDays, expandGrantPermissions } from '../helpers';
import type { AccessRequestItem } from '../types';

interface UseOwnerRequestsParams {
  setRequests: Dispatch<SetStateAction<AccessRequestItem[]>>;
  refreshData: (options?: { silent?: boolean }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Phán Quyết Phê Duyệt / Từ Chối Xác Thực Máy Chủ Trước Khi Đóng Hộp Thoại (`useOwnerRequests`)
 * Mục đích: Bắt buộc `await` phản hồi thành công từ `POST /access-requests/:id/decide` trước khi đóng `<dialog>`, rút yêu cầu khỏi hàng đợi `PENDING` và hiện thông báo thành công; giữ nguyên hộp thoại để hiển thị lỗi nếu máy chủ từ chối (`400`/`403`/`409`/`500`).
 */
export function useOwnerRequests({
  setRequests,
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
    setErrorMessage(null);
    setSelectedRequest(req);
    setGrantAction(req.requestedAction);
    setGrantValidDays(calculateRequestedDays(req.requestedFrom, req.requestedUntil));
    setApproveOpen(true);
  }

  async function handleConfirmApprove() {
    if (!selectedRequest) return;
    const target = selectedRequest;
    const actionSnapshot = grantAction;
    const daysSnapshot = grantValidDays;

    setIsApproving(true);
    setErrorMessage(null);

    try {
      const grantedPermissions = expandGrantPermissions(actionSnapshot);
      await apiClient(`/access-requests/${target.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'APPROVED',
          validDays: daysSnapshot,
          permissions: grantedPermissions,
        }),
      });
      setApproveOpen(false);
      setSelectedRequest(null);
      setRequests((prev) => removeOptimisticById(prev, target.id));
      setMessage(
        `Đã phê duyệt yêu cầu và cấp quyền ${actionSnapshot} tài liệu cho ${target.requestorName} trong ${daysSnapshot} ngày.`,
      );
      void refreshData({ silent: true });
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

  async function handleRejectRequest(req: AccessRequestItem): Promise<boolean> {
    setErrorMessage(null);
    try {
      await apiClient(`/access-requests/${req.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'REJECTED',
          decisionNote: 'Chủ sở hữu từ chối cấp quyền truy cập.',
        }),
      });
      setRequests((prev) => removeOptimisticById(prev, req.id));
      setMessage(`Đã từ chối yêu cầu truy cập của ${req.requestorName}.`);
      void refreshData({ silent: true });
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể từ chối yêu cầu.'
          : 'Đã xảy ra lỗi khi từ chối yêu cầu.',
      );
      return false;
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
