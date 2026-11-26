'use client';

import { useRef, useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import {
  ACCESS_DURATION_DAY_MS,
  computeEffectiveAccessCeiling,
  resolveClassificationDefaultViewDays,
} from '@sda/contracts';
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
import type {
  AccessGrantItem,
  DocumentItem,
  GrantStatusFilter,
  RoleLookupItem,
  UserLookupItem,
} from '../types';
import type { OwnerTab } from './use-owner-data';

interface UseOwnerGrantsParams {
  currentUserId?: string | null | undefined;
  documents: DocumentItem[];
  activeDocuments?: DocumentItem[] | undefined;
  isLoadingGrantDocs?: boolean | undefined;
  grantsPage?: number | undefined;
  grantsCountOnPage?: number | undefined;
  grantsStatusFilter?: GrantStatusFilter | undefined;
  onLoadGrantsPage?:
    ((page: number, status?: GrantStatusFilter) => Promise<boolean> | void) | undefined;
  setGrants: Dispatch<SetStateAction<AccessGrantItem[]>>;
  setActiveGrantsCount: Dispatch<SetStateAction<number>>;
  usersLookup: UserLookupItem[];
  rolesLookup: RoleLookupItem[];
  ensureGrantLookups?: () => Promise<void>;
  ensureGrantDocuments?: (() => Promise<DocumentItem[]>) | undefined;
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setDialogError: (msg: string | null) => void;
}

/**
 * Thuật toán: Cấp Quyền Trực Tiếp Có Thời Hạn & Thu Hồi Giấy Phép Theo Bộ Lọc Trạng Thái (`useOwnerGrants`, BUG-099, BUG-102)
 * Mục đích:
 *   - Chặn đóng hộp thoại khi đang gửi yêu cầu cấp quyền hoặc thu hồi quyền (`isSubmittingDirectGrant` / `isRevoking`).
 *   - Khi thu hồi quyền thành công: loại bỏ ngay dòng đã thu hồi nếu bộ lọc đang ở `'ACTIVE'` hoặc `'SUSPENDED'`, hoặc chuyển trạng thái sang `'REVOKED'` khi lọc `'ALL'` / `'REVOKED'`.
 */
export function useOwnerGrants({
  currentUserId,
  documents,
  activeDocuments = [],
  isLoadingGrantDocs = false,
  grantsPage = 1,
  grantsCountOnPage = 0,
  grantsStatusFilter = 'ALL',
  onLoadGrantsPage,
  setGrants,
  setActiveGrantsCount,
  usersLookup,
  rolesLookup,
  ensureGrantLookups,
  ensureGrantDocuments,
  refreshData,
  setMessage,
  setDialogError,
}: UseOwnerGrantsParams) {
  const nonActiveDocIds = new Set(documents.filter((d) => d.status !== 'ACTIVE').map((d) => d.id));
  const grantableById = new Map<string, DocumentItem>();
  for (const doc of filterGrantableDocuments(documents)) {
    grantableById.set(doc.id, doc);
  }
  for (const doc of filterGrantableDocuments(activeDocuments)) {
    if (!nonActiveDocIds.has(doc.id) && !grantableById.has(doc.id)) {
      grantableById.set(doc.id, doc);
    }
  }
  const grantableDocuments = [...grantableById.values()];
  const eligibleUsers = filterGrantEligibleUsers(usersLookup, currentUserId);
  const grantModalOpenSeqRef = useRef(0);
  const userTouchedGrantFormRef = useRef(false);

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

  const [revokeOpen, setRevokeOpenState] = useState(false);
  const [selectedGrant, setSelectedGrant] = useState<AccessGrantItem | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);

  const directDocId = directDocIdOverride || grantableDocuments[0]?.id || '';
  const directUserId = directUserIdOverride || eligibleUsers[0]?.id || '';
  const directRoleId = directRoleIdOverride || rolesLookup[0]?.id || '';

  function resolveInitialGrantUntil(doc?: DocumentItem, fromDate: Date = new Date()): string {
    const defaultDays = Math.min(
      GRANT_MAX_DURATION_DAYS,
      resolveClassificationDefaultViewDays(doc?.classificationCode, doc?.defaultViewDays),
    );
    const ceiling = computeEffectiveAccessCeiling({
      fromDate,
      maxDurationDays: GRANT_MAX_DURATION_DAYS,
      retentionUntil: doc?.retentionUntil,
      timezoneMode: 'safe-local',
    });
    const desired = new Date(fromDate.getTime() + defaultDays * ACCESS_DURATION_DAY_MS);
    const clamped =
      !ceiling.isRetentionExpired && desired.getTime() > ceiling.maxUntil.getTime()
        ? ceiling.maxUntil
        : desired;
    return toLocalISO(clamped);
  }

  function resetDirectGrantForm(explicitInitialDoc?: DocumentItem, now: Date = new Date()) {
    const initialDoc = explicitInitialDoc ?? grantableDocuments[0];
    setDirectDocIdOverride('');
    setDirectPrincipalType('USER');
    setDirectUserIdOverride('');
    setDirectRoleIdOverride('');
    setDirectPermissionMode('VIEW');
    setDirectValidFrom(toLocalISO(now));
    setDirectValidUntil(resolveInitialGrantUntil(initialDoc, now));
  }

  function handleSelectDirectDocId(nextDocId: string) {
    userTouchedGrantFormRef.current = true;
    setDirectDocIdOverride(nextDocId);
    const nextDoc = grantableDocuments.find((d) => d.id === nextDocId);
    if (nextDoc) {
      if (!nextDoc.allowDownload && directPermissionMode === 'DOWNLOAD') {
        setDirectPermissionMode('VIEW');
      }
      const parsedFrom = new Date(directValidFrom);
      const fromRef = Number.isNaN(parsedFrom.getTime()) ? new Date() : parsedFrom;
      setDirectValidUntil(resolveInitialGrantUntil(nextDoc, fromRef));
    }
  }

  function handleDirectGrantOpenChange(open: boolean) {
    if (!open && isSubmittingDirectGrant) return;
    if (!open) {
      grantModalOpenSeqRef.current += 1;
      userTouchedGrantFormRef.current = false;
      setDialogError(null);
      resetDirectGrantForm();
    }
    setDirectGrantOpen(open);
  }

  function handleRevokeOpenChange(open: boolean) {
    if (!open && isRevoking) return;
    if (!open) {
      setDialogError(null);
    }
    setRevokeOpenState(open);
  }

  function openDirectGrantModal() {
    setDialogError(null);
    const openSeq = ++grantModalOpenSeqRef.current;
    userTouchedGrantFormRef.current = false;
    void ensureGrantLookups?.();
    const initialDoc = grantableDocuments[0];
    const now = new Date();
    resetDirectGrantForm(initialDoc, now);
    setDirectGrantOpen(true);

    if (!initialDoc && ensureGrantDocuments) {
      void ensureGrantDocuments().then((loadedDocs) => {
        if (grantModalOpenSeqRef.current !== openSeq || userTouchedGrantFormRef.current) {
          return;
        }
        const firstLoadedDoc = filterGrantableDocuments(loadedDocs)[0];
        if (!firstLoadedDoc) return;
        setDirectPermissionMode((prevMode) =>
          !firstLoadedDoc.allowDownload && prevMode === 'DOWNLOAD' ? 'VIEW' : prevMode,
        );
        setDirectValidUntil(resolveInitialGrantUntil(firstLoadedDoc, now));
      });
    }
  }

  async function handleCreateDirectGrant(e: FormEvent) {
    e.preventDefault();
    const selectedDoc = grantableDocuments.find((d) => d.id === directDocId);
    if (!selectedDoc) {
      setDialogError('Vui lòng chọn tài liệu đang hiệu lực để cấp quyền.');
      return;
    }
    if (directPrincipalType === 'USER') {
      const selectedUser = eligibleUsers.find((u) => u.id === directUserId);
      if (!selectedUser) {
        setDialogError('Vui lòng chọn người dùng hợp lệ được cấp quyền.');
        return;
      }
      if (
        shouldWarnGrantClearance({
          principalType: 'USER',
          document: selectedDoc,
          user: selectedUser,
        })
      ) {
        setDialogError(
          `Người dùng ${selectedUser.fullName} có cấp thẩm quyền (Cấp ${selectedUser.clearanceRank}) thấp hơn mức độ mật của tài liệu (Cấp ${selectedDoc.classificationRank ?? 0}).`,
        );
        return;
      }
    } else if (!rolesLookup.some((r) => r.id === directRoleId)) {
      setDialogError('Vui lòng chọn vai trò được cấp quyền.');
      return;
    }

    if (directPermissionMode === 'DOWNLOAD' && !selectedDoc.allowDownload) {
      setDialogError('Mức độ mật của tài liệu này không cho phép cấp quyền tải về.');
      return;
    }

    const timeError = validateDirectGrantTimeRange(directValidFrom, directValidUntil, {
      maxDurationDays: GRANT_MAX_DURATION_DAYS,
      retentionUntil: selectedDoc.retentionUntil,
    });
    if (timeError) {
      setDialogError(timeError);
      return;
    }

    setIsSubmittingDirectGrant(true);
    setDialogError(null);

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

      setIsSubmittingDirectGrant(false);
      setDirectGrantOpen(false);
      resetDirectGrantForm();
      setMessage('Đã cấp quyền truy cập trực tiếp thành công.');
      void refreshData({ silent: true, scope: 'grants' });
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể cấp quyền truy cập.'
          : 'Đã xảy ra lỗi khi cấp quyền truy cập.',
      );
      setIsSubmittingDirectGrant(false);
    }
  }

  function openRevokeModal(grant: AccessGrantItem) {
    setDialogError(null);
    setSelectedGrant(grant);
    setRevokeReason('');
    setRevokeOpenState(true);
  }

  async function handleConfirmRevoke(e: FormEvent) {
    e.preventDefault();
    if (!selectedGrant) return;

    const trimmedReason = revokeReason.trim();
    if (trimmedReason.length < 10) {
      setDialogError('Lý do thu hồi phải có tối thiểu 10 ký tự để lưu nhật ký kiểm toán.');
      return;
    }
    if (trimmedReason.length > 500) {
      setDialogError('Lý do thu hồi không được vượt quá 500 ký tự.');
      return;
    }

    const target = selectedGrant;
    setIsRevoking(true);
    setDialogError(null);

    try {
      await apiClient(`/access-grants/${target.id}/revoke`, {
        method: 'POST',
        body: JSON.stringify({
          reason: trimmedReason,
          expectedVersion: target.version,
        }),
      });
      setIsRevoking(false);
      setRevokeOpenState(false);
      setSelectedGrant(null);
      setRevokeReason('');
      if (grantsStatusFilter === 'ACTIVE' || grantsStatusFilter === 'SUSPENDED') {
        setGrants((prev) => prev.filter((item) => item.id !== target.id));
        if (grantsPage > 1 && grantsCountOnPage <= 1) {
          void onLoadGrantsPage?.(grantsPage - 1, grantsStatusFilter);
        }
      } else {
        setGrants((prev) => applyOptimisticStatusById(prev, target.id, 'REVOKED'));
      }
      if (target.status === 'ACTIVE') {
        setActiveGrantsCount((prev) => Math.max(0, prev - 1));
      }
      setMessage(
        `Đã thu hồi quyền truy cập của ${target.principalName}. Mọi phiên đọc đang mở đã được ngắt ngay lập tức.`,
      );
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể thu hồi quyền.'
          : 'Đã xảy ra lỗi khi thu hồi quyền truy cập.',
      );
      setIsRevoking(false);
    }
  }

  return {
    grantableDocuments,
    isLoadingGrantDocs,
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
    setDirectPermissionMode: (mode: 'VIEW' | 'DOWNLOAD') => {
      userTouchedGrantFormRef.current = true;
      setDirectPermissionMode(mode);
    },
    directValidFrom,
    setDirectValidFrom: (value: string) => {
      userTouchedGrantFormRef.current = true;
      setDirectValidFrom(value);
    },
    directValidUntil,
    setDirectValidUntil: (value: string) => {
      userTouchedGrantFormRef.current = true;
      setDirectValidUntil(value);
    },
    isSubmittingDirectGrant,
    openDirectGrantModal,
    handleCreateDirectGrant,
    revokeOpen,
    setRevokeOpen: handleRevokeOpenChange,
    selectedGrant,
    revokeReason,
    setRevokeReason,
    isRevoking,
    openRevokeModal,
    handleConfirmRevoke,
  };
}
