'use client';

import { useState } from 'react';
import { apiClient } from '@/lib/api-client';
import type { ClassificationHistoryItem, DocumentItem, DocumentVersionItem } from '../types';

/**
 * Thuật toán: Mở Tức Thì Hộp Thoại Lịch Sử Phiên Bản & Lịch Sử Phân Loại SCD Loại 2 (`useDocumentHistory`)
 * Mục đích: Mở hộp thoại ngay dưới `16ms` khi nhấp chuột, xóa dữ liệu cũ của tài liệu trước để tránh nháy sai lệch và nạp bất đồng bộ danh sách băm SHA-256 / biến động mức mật.
 */
export function useDocumentHistory() {
  const [versionHistoryOpen, setVersionHistoryOpen] = useState(false);
  const [docVersions, setDocVersions] = useState<DocumentVersionItem[]>([]);
  const [isLoadingVersions, setIsLoadingVersions] = useState(false);
  const [docForVersions, setDocForVersions] = useState<DocumentItem | null>(null);

  const [classHistoryOpen, setClassHistoryOpen] = useState(false);
  const [docClassHistory, setDocClassHistory] = useState<ClassificationHistoryItem[]>([]);
  const [isLoadingClassHistory, setIsLoadingClassHistory] = useState(false);
  const [docForClassHistory, setDocForClassHistory] = useState<DocumentItem | null>(null);

  async function handleOpenVersionHistory(doc: DocumentItem) {
    setDocForVersions(doc);
    setDocVersions([]);
    setIsLoadingVersions(true);
    setVersionHistoryOpen(true);
    try {
      const res = await apiClient<DocumentVersionItem[] | { data: DocumentVersionItem[] }>(
        `/documents/${doc.id}/versions`,
      );
      setDocVersions(Array.isArray(res) ? res : res.data || []);
    } catch {
      setDocVersions([]);
    } finally {
      setIsLoadingVersions(false);
    }
  }

  async function handleOpenClassHistory(doc: DocumentItem) {
    setDocForClassHistory(doc);
    setDocClassHistory([]);
    setIsLoadingClassHistory(true);
    setClassHistoryOpen(true);
    try {
      const res = await apiClient<
        ClassificationHistoryItem[] | { data: ClassificationHistoryItem[] }
      >(`/documents/${doc.id}/classification-history`);
      setDocClassHistory(Array.isArray(res) ? res : res.data || []);
    } catch {
      setDocClassHistory([]);
    } finally {
      setIsLoadingClassHistory(false);
    }
  }

  return {
    versionHistoryOpen,
    setVersionHistoryOpen,
    docVersions,
    isLoadingVersions,
    docForVersions,
    handleOpenVersionHistory,
    classHistoryOpen,
    setClassHistoryOpen,
    docClassHistory,
    isLoadingClassHistory,
    docForClassHistory,
    handleOpenClassHistory,
  };
}
