'use client';

import { useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import {
  filterGrantEligibleUsers,
  filterGrantableDocuments,
  GRANT_MAX_DURATION_DAYS,
  shouldWarnGrantClearance,
  validateDirectGrantTimeRange,
} from '../grant-helpers';
import { expandGrantPermissions, toLocalISO } from '../helpers';
import type { AccessGrantItem, DocumentItem, RoleLookupItem, UserLookupItem } from '../types';
import type { OwnerTab } from './use-owner-data';

interface UseOwnerGrantsParams {
  currentUserId?: string | null | undefined;
  documents: DocumentItem[];
  setGrants: Dispatch<SetStateAction<AccessGrantItem[]>>;
  setActiveGrantsCount: Dispatch<SetStateAction<number>>;
  usersLookup: UserLookupItem[];
  rolesLookup: RoleLookupItem[];
  ensureGrantLookups?: () => Promise<void>;
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Cấp Quyền Trực Tiếp Có Thời Hạn & Thu Hồi Giấy Phép Xác Thực Máy Chủ (`useOwnerGrants`)
 * Mục đích:
 *   - Tải lười danh sách người dùng và vai trò đúng lúc mở hộp thoại cấp quyền, tự động đồng bộ mục chọn mặc định khi dữ liệu về.
 *   - Cập nhật trạng thái thu hồi trực tiếp trên state và chỉ làm mới cục bộ tab `grants` sau khi cấp quyền mới.
 */
export function useOwnerGrants({
  currentUserId,
  documents,
  setGrants,
  setActiveGrantsCount,
  usersLookup,
  rolesLookup,
  ensureGrantLookups,
  refreshData,
  setMessage,
  setErrorMessage,
}: UseOwnerGrantsParams) {
  const grantableDocuments = filterGrantableDocuments(documents);
  const eligibleUsers = filterGrantEligibleUsers(usersLookup, currentUserId);

  const [directGrantOpen, setDirectGrantOpen] = useState(false);
  const [directDocIdOverride, setDirectDocIdOverride] = useState('');
  const [directPrincipalType, setDirectPrincipalType] = useState<'USER' | 'ROLE'>('USER');
  const [directUserIdOverride, setDirectUserIdOverride] = useState('');
  const [directRoleIdOverride, setDirectRoleIdOverride] = useState('');
  const [directPermissionMode, setDirectPermissionMode] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [directValidFrom, setDirectValidFrom] = useState(() => toLocalISO(new Date()));
  const [directValidUntil, setDirectValidUntil] = useState(() =>
    toLocalISO(new Date(Date.now() + 7 * 86_400_000)),
  );
  const [isSubmittingDirectGrant, setIsSubmittingDirectGrant] = useState(false);

  const [revokeOpen, setRevokeOpen] = useState(false);
  const [selectedGrant, setSelectedGrant] = useState<AccessGrantItem | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);

  const directDocId = directDocIdOverride || grantableDocuments[0]?.id || '';
  const directUserId = directUserIdOverride || eligibleUsers[0]?.id || '';
  const directRoleId = directRoleIdOverride || rolesLookup[0]?.id || '';

  function resetDirectGrantForm() {
    setDirectDocIdOverride('');
    setDirectPrincipalType('USER');
    setDirectUserIdOverride('');
    setDirectRoleIdOverride('');
    setDirectPermissionMode('VIEW');
    setDirectValidFrom(toLocalISO(new Date()));
    setDirectValidUntil(toLocalISO(new Date(Date.now() + 7 * 86_400_000)));
  }

  function handleSelectDirectDocId(nextDocId: string) {
    setDirectDocIdOverride(nextDocId);
    const nextDoc = grantableDocuments.find((d) => d.id === nextDocId);
    if (nextDoc && !nextDoc.allowDownload && directPermissionMode === 'DOWNLOAD') {
      setDirectPermissionMode('VIEW');
    }
  }

  function handleDirectGrantOpenChange(open: boolean) {
    setDirectGrantOpen(open);
    if (!open) {
      setErrorMessage(null);
      resetDirectGrantForm();
    }
  }

  function openDirectGrantModal() {
    setErrorMessage(null);
    void ensureGrantLookups?.();
    resetDirectGrantForm();
    setDirectGrantOpen(true);
  }

  async function handleCreateDirectGrant(e: FormEvent) {
    e.preventDefault();
    const selectedDoc = grantableDocuments.find((d) => d.id === directDocId);
    if (!selectedDoc) {
      setErrorMessage('Vui lòng chọn tài liệu đang hiệu lực để cấp quyền.');
      return;
    }
    if (directPrincipalType === 'USER') {
      const selectedUser = eligibleUsers.find((u) => u.id === directUserId);
      if (!selectedUser) {
        setErrorMessage('Vui lòng chọn người dùng hợp lệ được cấp quyền.');
        return;
      }
      if (
        shouldWarnGrantClearance({
          principalType: 'USER',
          document: selectedDoc,
          user: selectedUser,
        })
      ) {
        setErrorMessage(
          `Người dùng ${selectedUser.fullName} có cấp thẩm quyền (Cấp ${selectedUser.clearanceRank}) thấp hơn mức độ mật của tài liệu (Cấp ${selectedDoc.classificationRank ?? 0}).`,
        );
        return;
      }
    } else if (!rolesLookup.some((r) => r.id === directRoleId)) {
      setErrorMessage('Vui lòng chọn vai trò được cấp quyền.');
      return;
    }

    if (directPermissionMode === 'DOWNLOAD' && !selectedDoc.allowDownload) {
      setErrorMessage('Mức độ mật của tài liệu này không cho phép cấp quyền tải về.');
      return;
    }

    const timeError = validateDirectGrantTimeRange(directValidFrom, directValidUntil, {
      maxDurationDays: GRANT_MAX_DURATION_DAYS,
    });
    if (timeError) {
      setErrorMessage(timeError);
      return;
    }

    setIsSubmittingDirectGrant(true);
    setErrorMessage(null);

    try {
      const normalizedPermissions = expandGrantPermissions(directPermissionMode);
      const payload: {
        documentId: string;
        principalType: 'USER' | 'ROLE';
        principalUserId?: string;
        principalRoleId?: string;
        permissions: ('VIEW' | 'DOWNLOAD')[];
        validFrom: string;
        validUntil: string;
      } = {
        documentId: selectedDoc.id,
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
      resetDirectGrantForm();
      setMessage('Đã cấp quyền truy cập trực tiếp thành công.');
      void refreshData({ silent: true, scope: 'grants' });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể cấp quyền truy cập.'
          : 'Đã xảy ra lỗi khi cấp quyền truy cập.',
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
      setErrorMessage('Lý do thu hồi phải có tối thiểu 10 ký tự để lưu nhật ký kiểm toán.');
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
      if (target.status === 'ACTIVE') {
        setActiveGrantsCount((prev) => Math.max(0, prev - 1));
      }
      setMessage(
        `Đã thu hồi quyền truy cập của ${target.principalName}. Mọi phiên đọc đang mở đã được ngắt ngay lập tức.`,
      );
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
    grantableDocuments,
    eligibleUsers,
    directGrantOpen,
    setDirectGrantOpen: handleDirectGrantOpenChange,
    directDocId,
    setDirectDocId: handleSelectDirectDocId,
    directPrincipalType,
    setDirectPrincipalType,
    directUserId,
    setDirectUserId: setDirectUserIdOverride,
    directRoleId,
    setDirectRoleId: setDirectRoleIdOverride,
    directPermissionMode,
    setDirectPermissionMode,
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
