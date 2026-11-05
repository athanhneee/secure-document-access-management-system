'use client';

import { useState, type Dispatch, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { removeOptimisticById } from '@/lib/optimistic-state';
import { calculateRequestedDays, expandGrantPermissions } from '../helpers';
import type { AccessRequestItem } from '../types';

interface UseOwnerRequestsParams {
  requests: AccessRequestItem[];
  setRequests: Dispatch<SetStateAction<AccessRequestItem[]>>;
  refreshData: (options?: { silent?: boolean }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Phán Quyết Phê Duyệt / Từ Chối Lạc Quan Kèm Hoàn Tác Tự Động (`useOwnerRequests`)
 * Mục đích: Đóng hộp thoại và rút ngay yêu cầu đã xử lý khỏi hàng đợi `PENDING` trong `< 16ms`, bảo toàn quyền nền `DOWNLOAD => ['VIEW', 'DOWNLOAD']` và tự động hoàn trả bản ghi nếu máy chủ báo lỗi.
 */
export function useOwnerRequests({
  requests,
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
    setSelectedRequest(req);
    setGrantAction(req.requestedAction);
    setGrantValidDays(calculateRequestedDays(req.requestedFrom, req.requestedUntil));
    setApproveOpen(true);
  }

  async function handleConfirmApprove() {
    if (!selectedRequest) return;
    const target = selectedRequest;
    const previousRequests = requests;
    const actionSnapshot = grantAction;
    const daysSnapshot = grantValidDays;

    setIsApproving(true);
    setErrorMessage(null);
    setApproveOpen(false);
    setSelectedRequest(null);
    setRequests((prev) => removeOptimisticById(prev, target.id));
    setMessage(
      `Đã phê duyệt yêu cầu và cấp quyền ${actionSnapshot} tài liệu cho ${target.requestorName} trong ${daysSnapshot} ngày.`,
    );

    try {
      // CONFLICT-RESOLVED: Khi phê duyệt mức DOWNLOAD, gửi đầy đủ ['VIEW', 'DOWNLOAD'] để người nhận vừa xem trực tuyến vừa tải bản sao.
      const grantedPermissions = expandGrantPermissions(actionSnapshot);
      await apiClient(`/access-requests/${target.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'APPROVED',
          validDays: daysSnapshot,
          permissions: grantedPermissions,
        }),
      });
      void refreshData({ silent: true });
    } catch (err) {
      setRequests(previousRequests);
      setMessage(null);
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
    const previousRequests = requests;
    setErrorMessage(null);
    setRequests((prev) => removeOptimisticById(prev, req.id));
    setMessage(`Đã từ chối yêu cầu truy cập của ${req.requestorName}.`);

    try {
      await apiClient(`/access-requests/${req.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'REJECTED',
          decisionNote: 'Chủ sở hữu từ chối cấp quyền truy cập.',
        }),
      });
      void refreshData({ silent: true });
    } catch (err) {
      setRequests(previousRequests);
      setMessage(null);
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
