'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { triggerBlobDownload } from '../helpers';
import type { DocumentItem } from '../types';

interface UseOwnerDeliveryParams {
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Mở Hộp Thoại Xem Trước Tức Thì Dưới 16ms & Tải Xuống Qua Vé Dùng Một Lần (`useOwnerDelivery`)
 * Mục đích: Mở khung xem trước Sandbox ngay lập tức (`< 0,1s`) trước khi khởi tạo phiên `VIEW`, xác thực chữ ký đầu `%PDF-` và chống tranh chấp phản hồi mạng qua `previewReqIdRef`.
 * Cơ chế hoạt động:
 *   - `handleOpenPreview`: Hiển thị hộp thoại phương thức ngay trong khung hình đầu tiên, tải phiên và luồng PDF gắn thủy vân ở nền; tự động đóng hộp thoại nếu máy chủ từ chối phiên.
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
  const previewReqIdRef = useRef(0);
  const previewPdfUrlRef = useRef<string | null>(null);

  useEffect(() => {
    previewPdfUrlRef.current = previewPdfUrl;
  }, [previewPdfUrl]);

  useEffect(() => {
    return () => {
      if (previewPdfUrlRef.current) {
        URL.revokeObjectURL(previewPdfUrlRef.current);
        previewPdfUrlRef.current = null;
      }
    };
  }, []);

  const handleClosePreview = useCallback(
    (open: boolean) => {
      if (!open) {
        previewReqIdRef.current += 1;
        setIsLoadingPreview(false);
      }
      setPreviewOpen(open);
      if (!open && previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
        setPreviewPdfUrl(null);
      }
    },
    [previewPdfUrl],
  );

  async function handleOpenPreview(doc: DocumentItem) {
    const reqId = ++previewReqIdRef.current;
    if (previewPdfUrl) {
      URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(null);
    }
    setErrorMessage(null);
    setPreviewDoc(doc);
    setPreviewSessionId(null);
    setPreviewPage(1);
    setPreviewTotalPages(1);
    setIsLoadingPreview(true);
    setPreviewOpen(true);

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      if (previewReqIdRef.current !== reqId) {
        return;
      }

      setPreviewSessionId(sessionResult.sessionId);

      // CONFLICT-RESOLVED: Chặn Fail-Closed khi tải luồng /preview thất bại hoặc sai chữ ký đầu %PDF- thay vì nuốt lỗi và dựng trang giả (CRIT-07).
      const pdfBlob = await apiDownload(
        `/documents/${doc.id}/preview?sessionId=${sessionResult.sessionId}`,
      );
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      if (!(await verifyPdfMagicBytes(pdfBlob))) {
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      if (pdfBlob.totalPages && pdfBlob.totalPages > 0) {
        setPreviewTotalPages(pdfBlob.totalPages);
      } else {
        setPreviewTotalPages(1);
      }
      const objectUrl = URL.createObjectURL(pdfBlob);
      setPreviewPdfUrl(objectUrl);
    } catch (err) {
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      setPreviewOpen(false);
      setPreviewSessionId(null);
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải luồng xem trước tài liệu an toàn.');
      } else if (err instanceof Error && err.message === 'INVALID_PDF_MAGIC_BYTES') {
        setErrorMessage('Luồng dữ liệu xem trước không phải tệp PDF hợp lệ (đã chặn Fail-Closed).');
      } else {
        setErrorMessage('Không thể tải luồng xem trước tài liệu an toàn.');
      }
    } finally {
      if (previewReqIdRef.current === reqId) {
        setIsLoadingPreview(false);
      }
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
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      if (previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
      }
      setPreviewPdfUrl(URL.createObjectURL(pageBlob));
      setPreviewPage(newPage);
    } catch (err) {
      handleClosePreview(false);
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải trang xem trước PDF.');
      } else {
        setErrorMessage('Luồng trang PDF không hợp lệ (đã đóng chế độ xem Fail-Closed).');
      }
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
