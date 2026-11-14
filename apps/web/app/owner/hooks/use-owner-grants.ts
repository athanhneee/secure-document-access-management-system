'use client';

import { useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import { expandGrantPermissions, toLocalISO } from '../helpers';
import type { AccessGrantItem, DocumentItem, RoleLookupItem, UserLookupItem } from '../types';

interface UseOwnerGrantsParams {
  documents: DocumentItem[];
  setGrants: Dispatch<SetStateAction<AccessGrantItem[]>>;
  usersLookup: UserLookupItem[];
  rolesLookup: RoleLookupItem[];
  refreshData: (options?: { silent?: boolean }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Cấp Quyền Trực Tiếp Có Thời Hạn & Thu Hồi Giấy Phép Xác Thực Máy Chủ (`useOwnerGrants`)
 * Mục đích: Kiểm định khoảng hiệu lực, chuẩn hóa tập quyền `DOWNLOAD => ['VIEW', 'DOWNLOAD']`, bắt buộc `await` phản hồi thành công từ máy chủ trước khi đóng `<dialog>` hoặc hiển thị thông báo xanh lá.
 */
export function useOwnerGrants({
  documents,
  setGrants,
  usersLookup,
  rolesLookup,
  refreshData,
  setMessage,
  setErrorMessage,
}: UseOwnerGrantsParams) {
  const [directGrantOpen, setDirectGrantOpen] = useState(false);
  const [directDocId, setDirectDocId] = useState('');
  const [directPrincipalType, setDirectPrincipalType] = useState<'USER' | 'ROLE'>('USER');
  const [directUserId, setDirectUserId] = useState('');
  const [directRoleId, setDirectRoleId] = useState('');
  const [directPermissions, setDirectPermissions] = useState<('VIEW' | 'DOWNLOAD')[]>(['VIEW']);
  const [directValidFrom, setDirectValidFrom] = useState(() => toLocalISO(new Date()));
  const [directValidUntil, setDirectValidUntil] = useState(() =>
    toLocalISO(new Date(Date.now() + 7 * 86400000)),
  );
  const [isSubmittingDirectGrant, setIsSubmittingDirectGrant] = useState(false);

  const [revokeOpen, setRevokeOpen] = useState(false);
  const [selectedGrant, setSelectedGrant] = useState<AccessGrantItem | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);

  function openDirectGrantModal() {
    setErrorMessage(null);
    if (documents[0] && !directDocId) {
      setDirectDocId(documents[0].id);
    }
    if (usersLookup[0] && !directUserId) {
      setDirectUserId(usersLookup[0].id);
    }
    if (rolesLookup[0] && !directRoleId) {
      setDirectRoleId(rolesLookup[0].id);
    }
    setDirectValidFrom(toLocalISO(new Date()));
    setDirectValidUntil(toLocalISO(new Date(Date.now() + 7 * 86400000)));
    setDirectGrantOpen(true);
  }

  async function handleCreateDirectGrant(e: FormEvent) {
    e.preventDefault();
    if (!directDocId) {
      setErrorMessage('Vui lòng chọn tài liệu cần cấp quyền.');
      return;
    }
    if (directPrincipalType === 'USER' && !directUserId) {
      setErrorMessage('Vui lòng chọn người dùng được cấp quyền.');
      return;
    }
    if (directPrincipalType === 'ROLE' && !directRoleId) {
      setErrorMessage('Vui lòng chọn vai trò được cấp quyền.');
      return;
    }
    if (directPermissions.length === 0) {
      setErrorMessage('Vui lòng chọn ít nhất một quyền (VIEW hoặc DOWNLOAD).');
      return;
    }
    if (!directValidFrom || !directValidUntil) {
      setErrorMessage('Vui lòng nhập đầy đủ thời gian bắt đầu và kết thúc hiệu lực.');
      return;
    }
    if (new Date(directValidUntil) <= new Date(directValidFrom)) {
      setErrorMessage('Thời gian kết thúc phải diễn ra sau thời gian bắt đầu.');
      return;
    }

    setIsSubmittingDirectGrant(true);
    setErrorMessage(null);

    try {
      const normalizedPermissions = expandGrantPermissions(directPermissions);
      const payload: {
        documentId: string;
        principalType: 'USER' | 'ROLE';
        principalUserId?: string;
        principalRoleId?: string;
        permissions: ('VIEW' | 'DOWNLOAD')[];
        validFrom: string;
        validUntil: string;
      } = {
        documentId: directDocId,
        principalType: directPrincipalType,
        permissions: normalizedPermissions,
        validFrom: new Date(directValidFrom).toISOString(),
        validUntil: new Date(directValidUntil).toISOString(),
      };

      if (directPrincipalType === 'USER') {
        payload.principalUserId = directUserId;
      } else {
        payload.principalRoleId = directRoleId;
      }

      await apiClient('/access-grants', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      setDirectGrantOpen(false);
      setDirectDocId('');
      setDirectUserId('');
      setDirectRoleId('');
      setMessage('Đã cấp giấy phép truy cập trực tiếp thành công.');
      void refreshData({ silent: true });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể cấp quyền truy cập.'
          : 'Đã xảy ra lỗi khi tạo giấy phép truy cập.',
      );
    } finally {
      setIsSubmittingDirectGrant(false);
    }
  }

  function openRevokeModal(grant: AccessGrantItem) {
    setErrorMessage(null);
    setSelectedGrant(grant);
    setRevokeReason('');
    setRevokeOpen(true);
  }

  async function handleConfirmRevoke(e: FormEvent) {
    e.preventDefault();
    if (!selectedGrant) return;

    const trimmedReason = revokeReason.trim();
    if (trimmedReason.length < 10) {
      setErrorMessage('Lý do thu hồi bắt buộc phải có ít nhất 10 ký tự để ghi nhật ký kiểm toán.');
      return;
    }

    const target = selectedGrant;
    setIsRevoking(true);
    setErrorMessage(null);

    try {
      await apiClient(`/access-grants/${target.id}/revoke`, {
        method: 'POST',
        body: JSON.stringify({
          reason: trimmedReason,
          expectedVersion: target.version,
        }),
      });
      setRevokeOpen(false);
      setSelectedGrant(null);
      setRevokeReason('');
      setGrants((prev) => applyOptimisticStatusById(prev, target.id, 'REVOKED'));
      setMessage(
        `Đã thu hồi quyền truy cập của ${target.principalName}. Mọi phiên làm việc đang chạy đã bị chấm dứt tức thì.`,
      );
      void refreshData({ silent: true });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể thu hồi quyền.'
          : 'Đã xảy ra lỗi khi thu hồi quyền truy cập.',
      );
    } finally {
      setIsRevoking(false);
    }
  }

  return {
    directGrantOpen,
    setDirectGrantOpen,
    directDocId,
    setDirectDocId,
    directPrincipalType,
    setDirectPrincipalType,
    directUserId,
    setDirectUserId,
    directRoleId,
    setDirectRoleId,
    directPermissions,
    setDirectPermissions,
    directValidFrom,
    setDirectValidFrom,
    directValidUntil,
    setDirectValidUntil,
    isSubmittingDirectGrant,
    openDirectGrantModal,
    handleCreateDirectGrant,
    revokeOpen,
    setRevokeOpen,
    selectedGrant,
    revokeReason,
    setRevokeReason,
    isRevoking,
    openRevokeModal,
    handleConfirmRevoke,
  };
}
