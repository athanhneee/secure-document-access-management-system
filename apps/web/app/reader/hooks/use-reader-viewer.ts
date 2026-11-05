'use client';

import { useState, useCallback } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { triggerWatermarkedDownload } from '../helpers';
import type { MyGrantedDoc } from '../types';

interface UseReaderViewerParams {
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Trình Xem Tài liệu Phiên PEP Kiểm soát & Tải xuống Qua Vé Dùng Một Lần (`useReaderViewer`)
 * Mục đích: Đàm phán phiên truy cập (`VIEW` / `DOWNLOAD`), kiểm chứng chữ ký đầu `%PDF-` trên từng trang PDF đã đóng dấu thủy vân và thu hồi tức thời Object URL.
 * Cơ chế hoạt động:
 *   - `handleOpenPreview` & `handlePageChange`: Kiểm tra 5 byte đầu `0x25 0x50 0x44 0x46 0x2D` qua `verifyPdfMagicBytes` trước khi nạp vào khung xem hộp cát, giải phóng URL trang trước để chống rò rỉ bộ nhớ.
 *   - `handleDownloadWithTicket`: Thực hiện quy trình 3 bước xin phiên `DOWNLOAD`, đổi vé ngắn hạn dùng một lần và tải bản sao gắn thủy vân.
 */
export function useReaderViewer({ setMessage, setErrorMessage }: UseReaderViewerParams) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<MyGrantedDoc | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewPdfUrl, setPreviewPdfUrl] = useState<string | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);

  const handleClosePreview = useCallback(
    (open: boolean) => {
      setPreviewOpen(open);
      if (!open && previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
        setPreviewPdfUrl(null);
      }
    },
    [previewPdfUrl],
  );

  async function handleOpenPreview(doc: MyGrantedDoc) {
    setIsLoadingPreview(true);
    setErrorMessage(null);
    if (previewPdfUrl) {
      URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(null);
    }

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      setPreviewDoc(doc);
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewPage(1);
      setPreviewOpen(true);

      try {
        const pdfBlob = await apiDownload(
          `/documents/${doc.documentId}/preview?sessionId=${sessionResult.sessionId}`,
        );
        if (!(await verifyPdfMagicBytes(pdfBlob))) {
          throw new Error('Invalid PDF stream header.');
        }
        if (pdfBlob.totalPages && pdfBlob.totalPages > 0) {
          setPreviewTotalPages(pdfBlob.totalPages);
        } else {
          setPreviewTotalPages(1);
        }
        const objectUrl = URL.createObjectURL(pdfBlob);
        setPreviewPdfUrl(objectUrl);
      } catch (streamErr) {
        console.warn(
          'Could not load binary PDF preview stream, using sandbox canvas fallback:',
          streamErr,
        );
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo phiên xem trước tài liệu.');
      } else {
        setErrorMessage('Không thể tạo phiên xem trước tài liệu.');
      }
    } finally {
      setIsLoadingPreview(false);
    }
  }

  async function handlePageChange(newPage: number) {
    if (newPage < 1 || newPage > previewTotalPages || !previewDoc || !previewSessionId) return;
    setIsLoadingPreview(true);
    try {
      const pdfBlob = await apiDownload(
        `/documents/${previewDoc.documentId}/preview/page/${newPage}?sessionId=${previewSessionId}`,
      );
      if (!(await verifyPdfMagicBytes(pdfBlob))) {
        throw new Error('Invalid PDF stream header.');
      }
      setPreviewPage(newPage);
      if (previewPdfUrl) URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(URL.createObjectURL(pdfBlob));
    } catch (err) {
      console.warn('Page preview error:', err);
    } finally {
      setIsLoadingPreview(false);
    }
  }

  async function handleDownloadWithTicket(doc: MyGrantedDoc) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này thuộc diện cấm tải theo chính sách phân loại mật.');
      return;
    }

    setDownloadingDocId(doc.documentId);
    setErrorMessage(null);

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'DOWNLOAD' }),
        },
      );

      const ticketResult = await apiClient<{ ticket: string; expiresAt: string }>(
        `/documents/${doc.documentId}/download-ticket`,
        {
          method: 'POST',
          body: JSON.stringify({ sessionId: sessionResult.sessionId }),
        },
      );

      const blob = await apiDownload(`/documents/download-with-ticket/${ticketResult.ticket}`);
      triggerWatermarkedDownload(blob, doc.documentCode);

      setMessage('Đã tạo và tải bản sao tài liệu có dấu bản quyền thành công.');
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo bản sao tải về.');
      }
    } finally {
      setDownloadingDocId(null);
    }
  }

  return {
    previewOpen,
    previewDoc,
    previewSessionId,
    previewPdfUrl,
    previewPage,
    previewTotalPages,
    isLoadingPreview,
    downloadingDocId,
    handleClosePreview,
    handleOpenPreview,
    handlePageChange,
    handleDownloadWithTicket,
  };
}
