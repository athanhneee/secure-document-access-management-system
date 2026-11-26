'use client';

import { useRef, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import type { ClassificationHistoryItem, DocumentItem, DocumentVersionItem } from '../types';

/**
 * Thuật toán: Mở Tức Thì Hộp Thoại Lịch Sử Phiên Bản & Lịch Sử Phân Loại Có Hủy Yêu Cầu Cũ (`useDocumentHistory`, BUG-102)
 * Mục đích: Mở hộp thoại ngay dưới `16ms` khi nhấp chuột, sử dụng `AbortController` hủy yêu cầu cũ khi đóng hoặc đổi tài liệu
 * và hiển thị lỗi truy vấn rõ ràng bên trong hộp thoại thay vì nuốt lỗi thành danh sách rỗng.
 */
export function useDocumentHistory(setDialogError?: (msg: string | null) => void) {
  const [versionHistoryOpen, setVersionHistoryOpenState] = useState(false);
  const [docVersions, setDocVersions] = useState<DocumentVersionItem[]>([]);
  const [isLoadingVersions, setIsLoadingVersions] = useState(false);
  const [docForVersions, setDocForVersions] = useState<DocumentItem | null>(null);
  const versionsAbortRef = useRef<AbortController | null>(null);

  const [classHistoryOpen, setClassHistoryOpenState] = useState(false);
  const [docClassHistory, setDocClassHistory] = useState<ClassificationHistoryItem[]>([]);
  const [isLoadingClassHistory, setIsLoadingClassHistory] = useState(false);
  const [docForClassHistory, setDocForClassHistory] = useState<DocumentItem | null>(null);
  const classAbortRef = useRef<AbortController | null>(null);

  function setVersionHistoryOpen(nextOpen: boolean) {
    if (!nextOpen) {
      versionsAbortRef.current?.abort();
      versionsAbortRef.current = null;
      setIsLoadingVersions(false);
      setDialogError?.(null);
    }
    setVersionHistoryOpenState(nextOpen);
  }

  function setClassHistoryOpen(nextOpen: boolean) {
    if (!nextOpen) {
      classAbortRef.current?.abort();
      classAbortRef.current = null;
      setIsLoadingClassHistory(false);
      setDialogError?.(null);
    }
    setClassHistoryOpenState(nextOpen);
  }

  async function handleOpenVersionHistory(doc: DocumentItem) {
    versionsAbortRef.current?.abort();
    const controller = new AbortController();
    versionsAbortRef.current = controller;

    setDialogError?.(null);
    setDocForVersions(doc);
    setDocVersions([]);
    setIsLoadingVersions(true);
    setVersionHistoryOpenState(true);
    try {
      const res = await apiClient<DocumentVersionItem[] | { data: DocumentVersionItem[] }>(
        `/documents/${doc.id}/versions`,
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      setDocVersions(Array.isArray(res) ? res : res.data || []);
    } catch (err) {
      if (controller.signal.aborted) return;
      setDocVersions([]);
      setDialogError?.(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể tải lịch sử phiên bản của tài liệu.',
      );
    } finally {
      if (versionsAbortRef.current === controller) {
        setIsLoadingVersions(false);
      }
    }
  }

  async function handleOpenClassHistory(doc: DocumentItem) {
    classAbortRef.current?.abort();
    const controller = new AbortController();
    classAbortRef.current = controller;

    setDialogError?.(null);
    setDocForClassHistory(doc);
    setDocClassHistory([]);
    setIsLoadingClassHistory(true);
    setClassHistoryOpenState(true);
    try {
      const res = await apiClient<
        ClassificationHistoryItem[] | { data: ClassificationHistoryItem[] }
      >(`/documents/${doc.id}/classification-history`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      setDocClassHistory(Array.isArray(res) ? res : res.data || []);
    } catch (err) {
      if (controller.signal.aborted) return;
      setDocClassHistory([]);
      setDialogError?.(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể tải lịch sử phân loại của tài liệu.',
      );
    } finally {
      if (classAbortRef.current === controller) {
        setIsLoadingClassHistory(false);
      }
    }
  }

  function updateDocForVersionsCurrentNo(docId: string, versionNo: number) {
    setDocForVersions((prev) =>
      prev && prev.id === docId ? { ...prev, currentVersionNo: versionNo } : prev,
    );
  }

  return {
    versionHistoryOpen,
    setVersionHistoryOpen,
    docVersions,
    isLoadingVersions,
    docForVersions,
    handleOpenVersionHistory,
    updateDocForVersionsCurrentNo,
    classHistoryOpen,
    setClassHistoryOpen,
    docClassHistory,
    isLoadingClassHistory,
    docForClassHistory,
    handleOpenClassHistory,
  };
}
