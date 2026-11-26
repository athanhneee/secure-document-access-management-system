'use client';

import { useRef, useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { formatRetentionDateIso } from '@sda/contracts';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById, removeOptimisticById } from '@/lib/optimistic-state';
import {
  isClassificationAllowedForClearance,
  validateRetentionDateInput,
  validateUploadFileInput,
} from '../helpers';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
  DocumentApiDto,
  DocumentItem,
  UserLookupItem,
} from '../types';
import type { OwnerTab } from './use-owner-data';

interface UseDocumentLifecycleParams {
  setDocuments: Dispatch<SetStateAction<DocumentItem[]>>;
  departments?: DepartmentLookupItem[] | undefined;
  classificationLevels: ClassificationLevelLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  eligibleTransferUsers?: UserLookupItem[] | undefined;
  userClearanceRank?: number | null | undefined;
  ensureUploadLookups?: (() => Promise<void>) | undefined;
  ensureGrantLookups?: (() => Promise<void>) | undefined;
  onVersionPromoted?: ((docId: string, versionNo: number) => void) | undefined;
  invalidateGrants?: (() => Promise<void>) | undefined;
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
  setDialogError: (msg: string | null) => void;
}

/**
 * Thuật toán: Quản Lý Vòng Đời Tài Liệu Có Khóa Nhấn Đúp Kích Hoạt, Chống Đua Mạng Phân Loại & Vô Hiệu Hóa Bộ Đệm Quyền (`useDocumentLifecycle`, BUG-099, BUG-100, BUG-101, BUG-102)
 * Mục đích:
 *   - Khóa chống nhấn đúp theo từng `doc.id` (`activatingDocIds`) và trả trực tiếp `Promise` khi kích hoạt bản nháp.
 *   - Bảo vệ hydration `GET /documents/:id` bằng bộ đếm `reclassFetchSeqRef` kết hợp cờ `userTouchedLevelRef`/`userTouchedCategoryRef` để mạng chậm không bao giờ ghi đè lựa chọn của người dùng.
 *   - Tự động gọi `invalidateGrants()` ngay sau khi `Reclassify` hoặc `Archive` để làm mới các giấy phép bị thu hồi/tạm ngưng dây chuyền.
 */
export function useDocumentLifecycle({
  setDocuments,
  departments = [],
  classificationLevels,
  businessCategories,
  eligibleTransferUsers = [],
  userClearanceRank,
  ensureUploadLookups,
  ensureGrantLookups,
  onVersionPromoted,
  invalidateGrants,
  refreshData,
  setMessage,
  setErrorMessage,
  setDialogError,
}: UseDocumentLifecycleParams) {
  const [activatingDocIds, setActivatingDocIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  );
  const activatingDocIdsRef = useRef<Set<string>>(new Set());

  const [reclassifyOpen, setReclassifyOpenState] = useState(false);
  const [docForReclassify, setDocForReclassify] = useState<DocumentItem | null>(null);
  const [reclassLevelId, setReclassLevelIdState] = useState<number>(1);
  const [reclassCategoryId, setReclassCategoryIdState] = useState<number>(1);
  const [reclassReason, setReclassReason] = useState('');
  const [isReclassifying, setIsReclassifying] = useState(false);
  const reclassFetchSeqRef = useRef(0);
  const userTouchedLevelRef = useRef(false);
  const userTouchedCategoryRef = useRef(false);

  const [newVersionOpen, setNewVersionOpenState] = useState(false);
  const [docForNewVersion, setDocForNewVersion] = useState<DocumentItem | null>(null);
  const [newVersionFile, setNewVersionFile] = useState<File | null>(null);
  const [newVersionNote, setNewVersionNote] = useState('');
  const [isUploadingVersion, setIsUploadingVersion] = useState(false);

  const [archiveOpen, setArchiveOpenState] = useState(false);
  const [docForArchive, setDocForArchive] = useState<DocumentItem | null>(null);
  const [archiveReason, setArchiveReason] = useState('');
  const [isArchiving, setIsArchiving] = useState(false);

  const [editMetaOpen, setEditMetaOpenState] = useState(false);
  const [docForEditMeta, setDocForEditMeta] = useState<DocumentItem | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editDepartmentId, setEditDepartmentId] = useState<number>(1);
  const [editRetentionDate, setEditRetentionDate] = useState('');
  const [isLoadingEditMeta, setIsLoadingEditMeta] = useState(false);
  const [isSavingMetadata, setIsSavingMetadata] = useState(false);
  const editMetaSeqRef = useRef(0);

  const [transferOwnerOpen, setTransferOwnerOpenState] = useState(false);
  const [docForTransfer, setDocForTransfer] = useState<DocumentItem | null>(null);
  const [transferNewOwnerOverride, setTransferNewOwnerOverride] = useState('');
  const [transferReason, setTransferReason] = useState('');
  const [isLoadingTransferUsers, setIsLoadingTransferUsers] = useState(false);
  const [isTransferringOwner, setIsTransferringOwner] = useState(false);

  const [settingVersionNo, setSettingVersionNo] = useState<number | null>(null);
  const transferNewOwnerId = transferNewOwnerOverride || eligibleTransferUsers[0]?.id || '';

  function setReclassifyOpen(nextOpen: boolean) {
    if (!nextOpen && isReclassifying) return;
    if (!nextOpen) {
      reclassFetchSeqRef.current += 1;
      userTouchedLevelRef.current = false;
      userTouchedCategoryRef.current = false;
      setDialogError(null);
    }
    setReclassifyOpenState(nextOpen);
  }

  function setNewVersionOpen(nextOpen: boolean) {
    if (!nextOpen && isUploadingVersion) return;
    if (!nextOpen) setDialogError(null);
    setNewVersionOpenState(nextOpen);
  }

  function setArchiveOpen(nextOpen: boolean) {
    if (!nextOpen && isArchiving) return;
    if (!nextOpen) setDialogError(null);
    setArchiveOpenState(nextOpen);
  }

  function setEditMetaOpen(nextOpen: boolean) {
    if (!nextOpen && isSavingMetadata) return;
    if (!nextOpen) {
      editMetaSeqRef.current += 1;
      setIsLoadingEditMeta(false);
      setDialogError(null);
    }
    setEditMetaOpenState(nextOpen);
  }

  function setTransferOwnerOpen(nextOpen: boolean) {
    if (!nextOpen && isTransferringOwner) return;
    if (!nextOpen) {
      setDialogError(null);
      setTransferNewOwnerOverride('');
      setTransferReason('');
    }
    setTransferOwnerOpenState(nextOpen);
  }

  function setReclassLevelId(nextId: number) {
    userTouchedLevelRef.current = true;
    setReclassLevelIdState(nextId);
  }

  function setReclassCategoryId(nextId: number) {
    userTouchedCategoryRef.current = true;
    setReclassCategoryIdState(nextId);
  }

  async function handleActivateDocument(doc: DocumentItem): Promise<void> {
    if (activatingDocIdsRef.current.has(doc.id)) return;
    activatingDocIdsRef.current.add(doc.id);
    setActivatingDocIds(new Set(activatingDocIdsRef.current));
    setErrorMessage(null);
    try {
      await apiClient(`/documents/${doc.id}/activate`, { method: 'POST' });
      setDocuments((prev) => applyOptimisticStatusById(prev, doc.id, 'ACTIVE'));
      setMessage(`Đã kích hoạt tài liệu "${doc.title}" thành công.`);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt tài liệu.'
          : 'Đã xảy ra lỗi khi kích hoạt tài liệu.',
      );
    } finally {
      activatingDocIdsRef.current.delete(doc.id);
      setActivatingDocIds(new Set(activatingDocIdsRef.current));
    }
  }

  function openReclassifyModal(doc: DocumentItem) {
    setDialogError(null);
    const seq = ++reclassFetchSeqRef.current;
    userTouchedLevelRef.current = false;
    userTouchedCategoryRef.current = false;

    const permittedLevels = classificationLevels.filter((lvl) =>
      isClassificationAllowedForClearance(lvl.rank, userClearanceRank),
    );
    const currentMatchedLevel = classificationLevels.find(
      (l) =>
        (doc.classificationLevelId && String(l.id) === String(doc.classificationLevelId)) ||
        l.code === doc.classificationCode,
    );
    const safeInitialLevel =
      currentMatchedLevel &&
      isClassificationAllowedForClearance(currentMatchedLevel.rank, userClearanceRank)
        ? currentMatchedLevel
        : (permittedLevels[permittedLevels.length - 1] ?? classificationLevels[0]);
    const fallbackLevelId = Number(safeInitialLevel?.id ?? doc.classificationLevelId ?? 1);
    const fallbackCategoryId = Number(
      doc.businessCategoryId ??
        businessCategories.find(
          (c) =>
            (doc.businessCategoryCode && c.code === doc.businessCategoryCode) ||
            (doc.businessCategoryName && c.name === doc.businessCategoryName),
        )?.id ??
        businessCategories[0]?.id ??
        1,
    );

    setDocForReclassify(doc);
    setReclassLevelIdState(fallbackLevelId);
    setReclassCategoryIdState(fallbackCategoryId);
    setReclassReason('');
    setReclassifyOpenState(true);

    if (!doc.classificationLevelId || !doc.businessCategoryId) {
      void apiClient<DocumentApiDto>(`/documents/${doc.id}`)
        .then((detail) => {
          if (reclassFetchSeqRef.current !== seq) return;
          const activeCls = detail.currentClassification;
          if (!activeCls) return;
          if (!userTouchedLevelRef.current && activeCls.classificationLevelId) {
            const hydratedId = Number(activeCls.classificationLevelId);
            const hydratedLvl = classificationLevels.find((l) => Number(l.id) === hydratedId);
            if (
              !hydratedLvl ||
              isClassificationAllowedForClearance(hydratedLvl.rank, userClearanceRank)
            ) {
              setReclassLevelIdState(hydratedId);
            }
          }
          if (!userTouchedCategoryRef.current && activeCls.businessCategoryId) {
            setReclassCategoryIdState(Number(activeCls.businessCategoryId));
          }
        })
        .catch(() => undefined);
    }
  }

  async function handleConfirmReclassify(e: FormEvent) {
    e.preventDefault();
    if (!docForReclassify) return;
    const trimmedReason = reclassReason.trim();
    if (!trimmedReason) {
      setDialogError('Vui lòng nhập lý do điều chỉnh mức độ mật.');
      return;
    }
    if (trimmedReason.length > 500) {
      setDialogError('Lý do điều chỉnh mức độ mật không được vượt quá 500 ký tự.');
      return;
    }

    const chosenLevel = classificationLevels.find((l) => Number(l.id) === Number(reclassLevelId));
    if (chosenLevel && !isClassificationAllowedForClearance(chosenLevel.rank, userClearanceRank)) {
      setDialogError(
        `Cấp thẩm quyền hiện tại (Cấp ${userClearanceRank ?? 0}) không đủ để phân loại tài liệu ở mức ${chosenLevel.name} (Cấp ${chosenLevel.rank}).`,
      );
      return;
    }

    setIsReclassifying(true);
    setDialogError(null);
    try {
      await apiClient(`/documents/${docForReclassify.id}/classify`, {
        method: 'POST',
        body: JSON.stringify({
          classificationLevelId: String(reclassLevelId),
          businessCategoryId: String(reclassCategoryId),
          reason: trimmedReason,
        }),
      });

      const targetTitle = docForReclassify.title;
      setIsReclassifying(false);
      setReclassifyOpenState(false);
      setDocForReclassify(null);
      setReclassReason('');
      setMessage(`Đã điều chỉnh mức độ mật tài liệu "${targetTitle}" thành công.`);
      await Promise.all([
        refreshData({ silent: true, scope: 'documents' }),
        invalidateGrants ? invalidateGrants() : Promise.resolve(),
      ]);
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể điều chỉnh phân loại tài liệu.'
          : 'Đã xảy ra lỗi khi điều chỉnh phân loại.',
      );
      setIsReclassifying(false);
    }
  }

  function openNewVersionModal(doc: DocumentItem) {
    setDialogError(null);
    setDocForNewVersion(doc);
    setNewVersionFile(null);
    setNewVersionNote('');
    setNewVersionOpenState(true);
  }

  async function handleConfirmNewVersion(e: FormEvent) {
    e.preventDefault();
    if (!docForNewVersion) return;
    const fileErr = validateUploadFileInput(newVersionFile);
    if (fileErr || !newVersionFile) {
      setDialogError(fileErr || 'Vui lòng chọn tệp phiên bản mới.');
      return;
    }

    setIsUploadingVersion(true);
    setDialogError(null);
    try {
      const formData = new FormData();
      formData.append('documentId', docForNewVersion.id);
      if (newVersionNote.trim()) {
        formData.append('changeNote', newVersionNote.trim());
      }
      formData.append('file', newVersionFile);

      const res = await apiClient<{ versionNo: number }>('/documents/upload', {
        method: 'POST',
        body: formData,
      });

      try {
        await apiClient(`/documents/${docForNewVersion.id}/current-version`, {
          method: 'POST',
          body: JSON.stringify({ versionNo: res.versionNo }),
        });
      } catch (vErr) {
        console.warn('Could not auto-set current version:', vErr);
      }

      const targetTitle = docForNewVersion.title;
      setIsUploadingVersion(false);
      setNewVersionOpenState(false);
      setDocForNewVersion(null);
      setNewVersionFile(null);
      setNewVersionNote('');
      setMessage(`Đã tải lên phiên bản ${res.versionNo} cho tài liệu "${targetTitle}".`);
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể tải lên phiên bản mới.'
          : 'Đã xảy ra lỗi khi cập nhật phiên bản.',
      );
      setIsUploadingVersion(false);
    }
  }

  function openArchiveModal(doc: DocumentItem) {
    setDialogError(null);
    setDocForArchive(doc);
    setArchiveReason('');
    setArchiveOpenState(true);
  }

  async function handleConfirmArchive(e: FormEvent) {
    e.preventDefault();
    if (!docForArchive) return;
    if (archiveReason.trim().length > 500) {
      setDialogError('Lý do lưu trữ không được vượt quá 500 ký tự.');
      return;
    }

    const target = docForArchive;
    const reasonPayload = archiveReason.trim() || 'Lưu trữ tài liệu theo quy chế an toàn';

    setIsArchiving(true);
    setDialogError(null);

    try {
      await apiClient(`/documents/${target.id}/archive`, {
        method: 'POST',
        body: JSON.stringify({ reason: reasonPayload }),
      });
      setIsArchiving(false);
      setArchiveOpenState(false);
      setDocForArchive(null);
      setArchiveReason('');
      setDocuments((prev) => applyOptimisticStatusById(prev, target.id, 'ARCHIVED'));
      setMessage(
        `Tài liệu "${target.title}" đã được chuyển vào lưu trữ. Mọi quyền hiệu lực đã tạm ngưng và phiên đọc đang mở đã được ngắt.`,
      );
      void invalidateGrants?.();
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể lưu trữ tài liệu.'
          : 'Đã xảy ra lỗi khi lưu trữ tài liệu.',
      );
      setIsArchiving(false);
    }
  }

  function openEditMetadataModal(doc: DocumentItem) {
    setDialogError(null);
    const seq = ++editMetaSeqRef.current;
    setDocForEditMeta(doc);
    setEditTitle(doc.title);
    setEditDescription(doc.description ?? '');
    setEditDepartmentId(Number(doc.departmentId ?? departments[0]?.id ?? 1));
    setEditRetentionDate(formatRetentionDateIso(doc.retentionUntil) ?? '');
    setEditMetaOpenState(true);
    setIsLoadingEditMeta(true);

    void Promise.allSettled([
      ensureUploadLookups ? ensureUploadLookups() : Promise.resolve(),
      apiClient<DocumentApiDto>(`/documents/${doc.id}`),
    ]).then(([, detailRes]) => {
      if (editMetaSeqRef.current !== seq) return;
      if (detailRes.status === 'fulfilled' && detailRes.value) {
        const dto = detailRes.value;
        setEditTitle(dto.title || doc.title);
        setEditDescription(dto.description ?? '');
        const resolvedDeptId = Number(
          dto.departmentId ??
            dto.department_id ??
            dto.department?.id ??
            dto.departments?.id ??
            doc.departmentId ??
            departments[0]?.id ??
            1,
        );
        if (Number.isFinite(resolvedDeptId) && resolvedDeptId > 0) {
          setEditDepartmentId(resolvedDeptId);
        }
        setEditRetentionDate(
          formatRetentionDateIso(dto.retentionUntil ?? dto.retention_until) ?? '',
        );
      }
      setIsLoadingEditMeta(false);
    });
  }

  async function handleConfirmEditMetadata(e: FormEvent) {
    e.preventDefault();
    if (!docForEditMeta) return;
    const trimmedTitle = editTitle.trim();
    if (!trimmedTitle) {
      setDialogError('Tiêu đề tài liệu không được để trống.');
      return;
    }
    if (trimmedTitle.length > 255) {
      setDialogError('Tiêu đề tài liệu không được vượt quá 255 ký tự.');
      return;
    }
    if (editDescription.length > 2000) {
      setDialogError('Mô tả tài liệu không được vượt quá 2000 ký tự.');
      return;
    }
    const retentionErr = validateRetentionDateInput(editRetentionDate);
    if (retentionErr) {
      setDialogError(retentionErr);
      return;
    }

    setIsSavingMetadata(true);
    setDialogError(null);
    const targetDoc = docForEditMeta;
    try {
      const payload: {
        title: string;
        description: string | null;
        departmentId?: string;
        retentionUntil: string | null;
      } = {
        title: trimmedTitle,
        description: editDescription.trim() ? editDescription.trim() : null,
        retentionUntil: editRetentionDate.trim() ? editRetentionDate.trim() : null,
      };
      if (Number.isFinite(editDepartmentId) && editDepartmentId > 0) {
        payload.departmentId = String(editDepartmentId);
      }

      await apiClient(`/documents/${targetDoc.id}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });

      setIsSavingMetadata(false);
      setEditMetaOpenState(false);
      setDocForEditMeta(null);
      setMessage(`Đã cập nhật thông tin tài liệu "${trimmedTitle}" thành công.`);
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể cập nhật thông tin tài liệu.'
          : 'Đã xảy ra lỗi khi cập nhật thông tin tài liệu.',
      );
      setIsSavingMetadata(false);
    }
  }

  function openTransferOwnerModal(doc: DocumentItem) {
    setDialogError(null);
    setDocForTransfer(doc);
    setTransferNewOwnerOverride('');
    setTransferReason('');
    setTransferOwnerOpenState(true);
    if (ensureGrantLookups) {
      setIsLoadingTransferUsers(true);
      void ensureGrantLookups().finally(() => {
        setIsLoadingTransferUsers(false);
      });
    }
  }

  async function handleConfirmTransferOwner(e: FormEvent) {
    e.preventDefault();
    if (!docForTransfer) return;
    if (!transferNewOwnerId || !eligibleTransferUsers.some((u) => u.id === transferNewOwnerId)) {
      setDialogError('Vui lòng chọn chủ sở hữu mới hợp lệ để bàn giao.');
      return;
    }
    const trimmedReason = transferReason.trim();
    if (!trimmedReason) {
      setDialogError('Vui lòng nhập lý do chuyển chủ sở hữu tài liệu.');
      return;
    }
    if (trimmedReason.length > 500) {
      setDialogError('Lý do chuyển chủ sở hữu không được vượt quá 500 ký tự.');
      return;
    }

    const targetDoc = docForTransfer;
    const recipient = eligibleTransferUsers.find((u) => u.id === transferNewOwnerId);
    setIsTransferringOwner(true);
    setDialogError(null);
    try {
      await apiClient(`/documents/${targetDoc.id}/transfer-owner`, {
        method: 'POST',
        body: JSON.stringify({
          newOwnerId: transferNewOwnerId,
          reason: trimmedReason,
        }),
      });
      setIsTransferringOwner(false);
      setTransferOwnerOpenState(false);
      setDocForTransfer(null);
      setTransferNewOwnerOverride('');
      setTransferReason('');
      setDocuments((prev) => removeOptimisticById(prev, targetDoc.id));
      setMessage(
        `Đã chuyển chủ sở hữu tài liệu "${targetDoc.title}" cho ${recipient?.fullName ?? 'chủ sở hữu mới'} thành công.`,
      );
      await Promise.all([
        refreshData({ silent: true, scope: 'documents' }),
        invalidateGrants ? invalidateGrants() : Promise.resolve(),
      ]);
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể chuyển chủ sở hữu tài liệu.'
          : 'Đã xảy ra lỗi khi chuyển chủ sở hữu tài liệu.',
      );
      setIsTransferringOwner(false);
    }
  }

  async function handleSetCurrentVersion(doc: DocumentItem, versionNo: number): Promise<void> {
    if (settingVersionNo !== null) return;
    setSettingVersionNo(versionNo);
    setDialogError(null);
    try {
      await apiClient(`/documents/${doc.id}/current-version`, {
        method: 'POST',
        body: JSON.stringify({ versionNo }),
      });
      setDocuments((prev) =>
        prev.map((item) => (item.id === doc.id ? { ...item, currentVersionNo: versionNo } : item)),
      );
      onVersionPromoted?.(doc.id, versionNo);
      setMessage(`Đã đặt Phiên bản ${versionNo} làm phiên bản hiện hành của "${doc.title}".`);
      void refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      setDialogError(
        err instanceof ApiError
          ? err.message || 'Không thể đặt phiên bản hiện hành.'
          : 'Đã xảy ra lỗi khi cập nhật phiên bản hiện hành.',
      );
    } finally {
      setSettingVersionNo(null);
    }
  }

  return {
    activatingDocIds,
    reclassifyOpen,
    setReclassifyOpen,
    docForReclassify,
    reclassLevelId,
    setReclassLevelId,
    reclassCategoryId,
    setReclassCategoryId,
    reclassReason,
    setReclassReason,
    isReclassifying,
    openReclassifyModal,
    handleConfirmReclassify,
    newVersionOpen,
    setNewVersionOpen,
    docForNewVersion,
    newVersionFile,
    setNewVersionFile,
    newVersionNote,
    setNewVersionNote,
    isUploadingVersion,
    openNewVersionModal,
    handleConfirmNewVersion,
    archiveOpen,
    setArchiveOpen,
    docForArchive,
    archiveReason,
    setArchiveReason,
    isArchiving,
    openArchiveModal,
    handleConfirmArchive,
    handleActivateDocument,
    editMetaOpen,
    setEditMetaOpen,
    docForEditMeta,
    editTitle,
    setEditTitle,
    editDescription,
    setEditDescription,
    editDepartmentId,
    setEditDepartmentId,
    editRetentionDate,
    setEditRetentionDate,
    isLoadingEditMeta,
    isSavingMetadata,
    openEditMetadataModal,
    handleConfirmEditMetadata,
    transferOwnerOpen,
    setTransferOwnerOpen,
    docForTransfer,
    transferNewOwnerId,
    setTransferNewOwnerId: setTransferNewOwnerOverride,
    transferReason,
    setTransferReason,
    isLoadingTransferUsers,
    isTransferringOwner,
    openTransferOwnerModal,
    handleConfirmTransferOwner,
    settingVersionNo,
    handleSetCurrentVersion,
  };
}
