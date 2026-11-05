'use client';

import { useState, useCallback } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { triggerBlobDownload } from '../helpers';
import type { DocumentItem } from '../types';

interface UseOwnerDeliveryParams {
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Xem trước Phiên Kiểm soát PEP & Tải xuống Qua Vé Dùng Một Lần (`useOwnerDelivery`)
 * Mục đích: Cấp phát phiên truy cập (`VIEW` / `DOWNLOAD`) đã thẩm định chính sách, xác thực chữ ký đầu `%PDF-` và quản lý vòng đời Object URL chống rò rỉ bộ nhớ.
 * Cơ chế hoạt động:
 *   - `handleOpenPreview` & `handlePageChange`: Khởi tạo phiên `VIEW`, tải luồng nhị phân trang PDF đã đóng dấu thủy vân, kiểm chứng magic bytes `0x25 0x50 0x44 0x46 0x2D` (`verifyPdfMagicBytes`) và thu hồi `ObjectURL` cũ ngay khi chuyển trang/đóng hộp thoại.
 *   - `handleDownloadWithTicket`: Thực thi giao thức 3 bước (mở phiên `DOWNLOAD` -> xin vé ngắn hạn dùng một lần `download-ticket` -> tải bản sao PDF gắn thủy vân).
 */
export function useOwnerDelivery({ setMessage, setErrorMessage }: UseOwnerDeliveryParams) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<DocumentItem | null>(null);
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

  async function handleOpenPreview(doc: DocumentItem) {
    setIsLoadingPreview(true);
    setErrorMessage(null);
    if (previewPdfUrl) {
      URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(null);
    }

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
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
          `/documents/${doc.id}/preview?sessionId=${sessionResult.sessionId}`,
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
        console.warn('Could not load binary PDF preview stream:', streamErr);
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
    if (!previewDoc || !previewSessionId || newPage === previewPage) return;
    setIsLoadingPreview(true);
    try {
      const pageBlob = await apiDownload(
        `/documents/${previewDoc.id}/preview/page/${newPage}?sessionId=${previewSessionId}`,
      );
      if (!(await verifyPdfMagicBytes(pageBlob))) {
        throw new Error('Invalid PDF stream header.');
      }
      if (previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
      }
      setPreviewPdfUrl(URL.createObjectURL(pageBlob));
      setPreviewPage(newPage);
    } catch (err) {
      console.error('Could not load page preview:', err);
    } finally {
      setIsLoadingPreview(false);
    }
  }

  async function handleDownloadWithTicket(doc: DocumentItem) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này thuộc diện cấm tải theo chính sách phân loại mật.');
      return;
    }

    setDownloadingDocId(doc.id);
    setErrorMessage(null);

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'DOWNLOAD' }),
        },
      );

      const ticketResult = await apiClient<{ ticket: string; expiresAt: string }>(
        `/documents/${doc.id}/download-ticket`,
        {
          method: 'POST',
          body: JSON.stringify({ sessionId: sessionResult.sessionId }),
        },
      );

      const blob = await apiDownload(`/documents/download-with-ticket/${ticketResult.ticket}`);
      triggerBlobDownload(blob, `${doc.documentCode || 'DOCUMENT'}_watermarked.pdf`);

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
