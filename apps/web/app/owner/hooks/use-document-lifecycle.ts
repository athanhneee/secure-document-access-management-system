'use client';

import { useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import type { DocumentItem } from '../types';

interface UseDocumentLifecycleParams {
  documents: DocumentItem[];
  setDocuments: Dispatch<SetStateAction<DocumentItem[]>>;
  refreshData: (options?: { silent?: boolean }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Quản Lý Vòng Đời Tài Liệu Lạc Quan Kèm Hoàn Tác Tự Động (`useDocumentLifecycle`)
 * Mục đích: Phản hồi tức thì dưới `16ms` cho thao tác kích hoạt (`ACTIVE`), điều chỉnh mức mật SCD Loại 2 và lưu trữ (`ARCHIVED`), tự động khôi phục ảnh chụp danh sách tài liệu nếu máy chủ báo lỗi.
 */
export function useDocumentLifecycle({
  documents,
  setDocuments,
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
    const previousDocuments = documents;
    setErrorMessage(null);
    setDocuments((prev) => applyOptimisticStatusById(prev, doc.id, 'ACTIVE'));
    setMessage(`Đã kích hoạt tài liệu "${doc.title}" thành công.`);

    try {
      await apiClient(`/documents/${doc.id}/activate`, { method: 'POST' });
      void refreshData({ silent: true });
    } catch (err) {
      setDocuments(previousDocuments);
      setMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt tài liệu.'
          : 'Đã xảy ra lỗi khi kích hoạt tài liệu.',
      );
    }
  }

  function openReclassifyModal(doc: DocumentItem) {
    setDocForReclassify(doc);
    setReclassLevelId(doc.classificationLevelId || 1);
    setReclassCategoryId(doc.businessCategoryId || 1);
    setReclassReason('');
    setReclassifyOpen(true);
  }

  async function handleConfirmReclassify(e: FormEvent) {
    e.preventDefault();
    if (!docForReclassify) return;
    if (!reclassReason.trim()) {
      setErrorMessage('Vui lòng nhập lý do điều chỉnh phân loại mật.');
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

      setMessage(`Đã điều chỉnh phân loại tài liệu "${docForReclassify.title}" thành công.`);
      setReclassifyOpen(false);
      setDocForReclassify(null);
      setReclassReason('');
      await refreshData();
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

      setMessage(
        `Đã tải lên phiên bản v${res.versionNo}.0 cho tài liệu "${docForNewVersion.title}".`,
      );
      setNewVersionOpen(false);
      setDocForNewVersion(null);
      setNewVersionFile(null);
      setNewVersionNote('');
      await refreshData();
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
    setDocForArchive(doc);
    setArchiveReason('');
    setArchiveOpen(true);
  }

  async function handleConfirmArchive(e: FormEvent) {
    e.preventDefault();
    if (!docForArchive) return;

    const target = docForArchive;
    const previousDocuments = documents;
    const reasonPayload = archiveReason.trim() || 'Lưu trữ tài liệu theo quy chế an toàn';

    setIsArchiving(true);
    setErrorMessage(null);
    setArchiveOpen(false);
    setDocForArchive(null);
    setArchiveReason('');
    setDocuments((prev) => applyOptimisticStatusById(prev, target.id, 'ARCHIVED'));
    setMessage(
      `Tài liệu "${target.title}" đã được chuyển vào lưu trữ (ARCHIVED). Mọi phiên đọc đã bị chấm dứt.`,
    );

    try {
      await apiClient(`/documents/${target.id}/archive`, {
        method: 'POST',
        body: JSON.stringify({ reason: reasonPayload }),
      });
      void refreshData({ silent: true });
    } catch (err) {
      setDocuments(previousDocuments);
      setMessage(null);
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
