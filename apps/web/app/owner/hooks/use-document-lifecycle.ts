'use client';

import { useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DocumentApiDto,
  DocumentItem,
} from '../types';
import type { OwnerTab } from './use-owner-data';

interface UseDocumentLifecycleParams {
  setDocuments: Dispatch<SetStateAction<DocumentItem[]>>;
  classificationLevels: ClassificationLevelLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Quản Lý Vòng Đời Tài Liệu Xác Thực Máy Chủ Trước Khi Đóng Hộp Thoại (`useDocumentLifecycle`)
 * Mục đích: Khởi tạo sẵn `classificationLevelId` và `businessCategoryId` hiện hành khi mở modal `Đổi mức mật`, đồng thời bắt buộc `await` phản hồi API thành công trước khi đóng `<dialog>` hoặc hiện thông báo xanh lá.
 */
export function useDocumentLifecycle({
  setDocuments,
  classificationLevels,
  businessCategories,
  refreshData,
  setMessage,
  setErrorMessage,
}: UseDocumentLifecycleParams) {
  const [reclassifyOpen, setReclassifyOpen] = useState(false);
  const [docForReclassify, setDocForReclassify] = useState<DocumentItem | null>(null);
  const [reclassLevelId, setReclassLevelId] = useState<number>(1);
  const [reclassCategoryId, setReclassCategoryId] = useState<number>(1);
  const [reclassReason, setReclassReason] = useState('');
  const [isReclassifying, setIsReclassifying] = useState(false);

  const [newVersionOpen, setNewVersionOpen] = useState(false);
  const [docForNewVersion, setDocForNewVersion] = useState<DocumentItem | null>(null);
  const [newVersionFile, setNewVersionFile] = useState<File | null>(null);
  const [newVersionNote, setNewVersionNote] = useState('');
  const [isUploadingVersion, setIsUploadingVersion] = useState(false);

  const [archiveOpen, setArchiveOpen] = useState(false);
  const [docForArchive, setDocForArchive] = useState<DocumentItem | null>(null);
  const [archiveReason, setArchiveReason] = useState('');
  const [isArchiving, setIsArchiving] = useState(false);

  async function handleActivateDocument(doc: DocumentItem) {
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
    }
  }

  function openReclassifyModal(doc: DocumentItem) {
    setErrorMessage(null);
    const fallbackLevelId = Number(
      doc.classificationLevelId ??
        classificationLevels.find((l) => l.code === doc.classificationCode)?.id ??
        classificationLevels[0]?.id ??
        1,
    );
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
    setReclassLevelId(fallbackLevelId);
    setReclassCategoryId(fallbackCategoryId);
    setReclassReason('');
    setReclassifyOpen(true);

    if (!doc.classificationLevelId || !doc.businessCategoryId) {
      void apiClient<DocumentApiDto>(`/documents/${doc.id}`)
        .then((detail) => {
          const activeCls = detail.currentClassification;
          if (!activeCls) return;
          if (activeCls.classificationLevelId) {
            setReclassLevelId(Number(activeCls.classificationLevelId));
          }
          if (activeCls.businessCategoryId) {
            setReclassCategoryId(Number(activeCls.businessCategoryId));
          }
        })
        .catch(() => undefined);
    }
  }

  async function handleConfirmReclassify(e: FormEvent) {
    e.preventDefault();
    if (!docForReclassify) return;
    if (!reclassReason.trim()) {
      setErrorMessage('Vui lòng nhập lý do điều chỉnh mức độ mật.');
      return;
    }

    setIsReclassifying(true);
    setErrorMessage(null);
    try {
      await apiClient(`/documents/${docForReclassify.id}/classify`, {
        method: 'POST',
        body: JSON.stringify({
          classificationLevelId: String(reclassLevelId),
          businessCategoryId: String(reclassCategoryId),
          reason: reclassReason.trim(),
        }),
      });

      const targetTitle = docForReclassify.title;
      setReclassifyOpen(false);
      setDocForReclassify(null);
      setReclassReason('');
      setMessage(`Đã điều chỉnh mức độ mật tài liệu "${targetTitle}" thành công.`);
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể điều chỉnh phân loại tài liệu.'
          : 'Đã xảy ra lỗi khi điều chỉnh phân loại.',
      );
    } finally {
      setIsReclassifying(false);
    }
  }

  function openNewVersionModal(doc: DocumentItem) {
    setErrorMessage(null);
    setDocForNewVersion(doc);
    setNewVersionFile(null);
    setNewVersionNote('');
    setNewVersionOpen(true);
  }

  async function handleConfirmNewVersion(e: FormEvent) {
    e.preventDefault();
    if (!docForNewVersion || !newVersionFile) {
      setErrorMessage('Vui lòng chọn tệp phiên bản mới.');
      return;
    }

    setIsUploadingVersion(true);
    setErrorMessage(null);
    try {
      const formData = new FormData();
      formData.append('documentId', docForNewVersion.id);
      formData.append('file', newVersionFile);
      if (newVersionNote.trim()) {
        formData.append('changeNote', newVersionNote.trim());
      }

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
      setNewVersionOpen(false);
      setDocForNewVersion(null);
      setNewVersionFile(null);
      setNewVersionNote('');
      setMessage(`Đã tải lên phiên bản ${res.versionNo} cho tài liệu "${targetTitle}".`);
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể tải lên phiên bản mới.'
          : 'Đã xảy ra lỗi khi cập nhật phiên bản.',
      );
    } finally {
      setIsUploadingVersion(false);
    }
  }

  function openArchiveModal(doc: DocumentItem) {
    setErrorMessage(null);
    setDocForArchive(doc);
    setArchiveReason('');
    setArchiveOpen(true);
  }

  async function handleConfirmArchive(e: FormEvent) {
    e.preventDefault();
    if (!docForArchive) return;

    const target = docForArchive;
    const reasonPayload = archiveReason.trim() || 'Lưu trữ tài liệu theo quy chế an toàn';

    setIsArchiving(true);
    setErrorMessage(null);

    try {
      await apiClient(`/documents/${target.id}/archive`, {
        method: 'POST',
        body: JSON.stringify({ reason: reasonPayload }),
      });
      setArchiveOpen(false);
      setDocForArchive(null);
      setArchiveReason('');
      setDocuments((prev) => applyOptimisticStatusById(prev, target.id, 'ARCHIVED'));
      setMessage(
        `Tài liệu "${target.title}" đã được chuyển vào lưu trữ. Mọi phiên đọc đang mở đã được ngắt.`,
      );
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu trữ tài liệu.'
          : 'Đã xảy ra lỗi khi lưu trữ tài liệu.',
      );
    } finally {
      setIsArchiving(false);
    }
  }

  return {
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
  };
}
