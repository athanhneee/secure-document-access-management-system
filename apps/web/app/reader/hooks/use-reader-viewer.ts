'use client';

import { useState, useCallback, useRef } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { triggerWatermarkedDownload } from '../helpers';
import type { MyGrantedDoc } from '../types';

interface UseReaderViewerParams {
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Mở Hộp Thoại Xem Trước Tức Thì Dưới 16ms & Kiểm Định Chữ Ký `%PDF-` Chống Tranh Chấp (`useReaderViewer`)
 * Mục đích: Hiển thị khung Sandbox xem trước ngay tức khắc khi người đọc nhấp chuột (`< 0,1s`) trong lúc đàm phán phiên `VIEW` và tải luồng PDF gắn thủy vân ở nền, đồng thời chặn phản hồi trễ bằng khóa phiên tăng dần `previewReqIdRef`.
 * Cơ chế hoạt động:
 *   - `handleOpenPreview`: Mở ngay hộp thoại phương thức ở trạng thái đang tải trước khi `await` API; nếu tạo phiên thất bại thì tự động đóng hộp thoại và hiển thị thông báo lỗi.
 *   - `verifyPdfMagicBytes` & `URL.revokeObjectURL`: Xác thực 5 byte đầu `0x25 0x50 0x44 0x46 0x2D` và thu hồi ngay Object URL khi đóng hoặc chuyển trang chống rò rỉ bộ nhớ.
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
  const previewReqIdRef = useRef(0);

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

  async function handleOpenPreview(doc: MyGrantedDoc) {
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
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      if (previewReqIdRef.current !== reqId) {
        return;
      }

      setPreviewSessionId(sessionResult.sessionId);

      try {
        const pdfBlob = await apiDownload(
          `/documents/${doc.documentId}/preview?sessionId=${sessionResult.sessionId}`,
        );
        if (previewReqIdRef.current !== reqId) {
          return;
        }
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
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      setPreviewOpen(false);
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo phiên xem trước tài liệu.');
      } else {
        setErrorMessage('Không thể tạo phiên xem trước tài liệu.');
      }
    } finally {
      if (previewReqIdRef.current === reqId) {
        setIsLoadingPreview(false);
      }
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
