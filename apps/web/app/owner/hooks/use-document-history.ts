'use client';

import { useState } from 'react';
import { apiClient } from '@/lib/api-client';
import type { ClassificationHistoryItem, DocumentItem, DocumentVersionItem } from '../types';

/**
 * Fetches on-demand version history (SHA-256 & malware scan status) and SCD Type 2
 * classification history records for a selected document.
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
