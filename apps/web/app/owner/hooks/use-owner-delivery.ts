'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { resolveSafeDownloadFilename } from '@/app/reader/helpers';
import { triggerBlobDownload } from '../helpers';
import type { DocumentItem } from '../types';

interface UseOwnerDeliveryParams {
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function endAccessSessionFireAndForget(sessionId: string | null): void {
  if (!sessionId || !UUID_RE.test(sessionId)) return;
  void apiClient(`/access-sessions/${encodeURIComponent(sessionId)}/end`, {
    method: 'POST',
    keepalive: true,
  }).catch(() => undefined);
}

/**
 * Thuật toán: Mở Hộp Thoại Xem Trước Canvas Tức Thì Dưới 16ms & Tải Xuống Kèm `X-Access-Session-Id` (`useOwnerDelivery`)
 * Mục đích: Mở khung xem trước ngay lập tức (`< 0,1s`) trước khi khởi tạo phiên `VIEW`, tải từng trang qua Canvas `Uint8Array` (không tạo `blob:` URL), xác thực chữ ký đầu `%PDF-` và chống tranh chấp phản hồi mạng qua `previewReqIdRef` trên cả lần mở đầu lẫn chuyển trang.
 */
export function useOwnerDelivery({ setMessage, setErrorMessage }: UseOwnerDeliveryParams) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<DocumentItem | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewVersionNo, setPreviewVersionNo] = useState<number | null>(null);
  const [previewPdfBytes, setPreviewPdfBytes] = useState<Uint8Array | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [previewPageError, setPreviewPageError] = useState<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);
  const previewReqIdRef = useRef(0);
  const activeSessionIdRef = useRef<string | null>(null);

  useEffect(() => {
    activeSessionIdRef.current = previewSessionId;
  }, [previewSessionId]);

  useEffect(() => {
    return () => {
      if (activeSessionIdRef.current) {
        endAccessSessionFireAndForget(activeSessionIdRef.current);
        activeSessionIdRef.current = null;
      }
    };
  }, []);

  const handleClosePreview = useCallback((open: boolean) => {
    if (!open) {
      previewReqIdRef.current += 1;
      setIsLoadingPreview(false);
      setPreviewPdfBytes(null);
      setPreviewPageError(null);
      const sid = activeSessionIdRef.current;
      activeSessionIdRef.current = null;
      setPreviewSessionId(null);
      setPreviewVersionNo(null);
      if (sid) {
        endAccessSessionFireAndForget(sid);
      }
    }
    setPreviewOpen(open);
  }, []);

  async function handleOpenPreview(doc: DocumentItem) {
    if (activeSessionIdRef.current) {
      endAccessSessionFireAndForget(activeSessionIdRef.current);
      activeSessionIdRef.current = null;
    }
    const reqId = ++previewReqIdRef.current;
    setPreviewPdfBytes(null);
    setPreviewPageError(null);
    setErrorMessage(null);
    setPreviewDoc(doc);
    setPreviewSessionId(null);
    setPreviewVersionNo(null);
    setPreviewPage(1);
    setPreviewTotalPages(1);
    setIsLoadingPreview(true);
    setPreviewOpen(true);

    try {
      const sessionResult = await apiClient<{ sessionId: string; versionNo?: number }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      if (previewReqIdRef.current !== reqId) {
        endAccessSessionFireAndForget(sessionResult.sessionId);
        return;
      }

      activeSessionIdRef.current = sessionResult.sessionId;
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewVersionNo(
        typeof sessionResult.versionNo === 'number' ? sessionResult.versionNo : null,
      );

      const pdfBlob = await apiDownload(`/documents/${doc.id}/preview/page/1`, {
        headers: { 'x-access-session-id': sessionResult.sessionId },
      });
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      if (!(await verifyPdfMagicBytes(pdfBlob))) {
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      const bytes = new Uint8Array(await pdfBlob.arrayBuffer());
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      setPreviewTotalPages(pdfBlob.totalPages && pdfBlob.totalPages > 0 ? pdfBlob.totalPages : 1);
      setPreviewPdfBytes(bytes);
    } catch (err) {
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      handleClosePreview(false);
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải bản xem trước tài liệu. Vui lòng thử lại.');
      } else if (err instanceof Error && err.message === 'INVALID_PDF_MAGIC_BYTES') {
        setErrorMessage('Dữ liệu bản xem trước không hợp lệ nên hệ thống không thể hiển thị.');
      } else {
        setErrorMessage('Không thể tải bản xem trước tài liệu. Vui lòng thử lại.');
      }
    } finally {
      if (previewReqIdRef.current === reqId) {
        setIsLoadingPreview(false);
      }
    }
  }

  async function handlePageChange(newPage: number) {
    if (!previewDoc || !previewSessionId || newPage < 1 || newPage > previewTotalPages) return;
    const reqId = ++previewReqIdRef.current;
    setIsLoadingPreview(true);
    setPreviewPageError(null);
    try {
      const pageBlob = await apiDownload(`/documents/${previewDoc.id}/preview/page/${newPage}`, {
        headers: { 'x-access-session-id': previewSessionId },
      });
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      if (!(await verifyPdfMagicBytes(pageBlob))) {
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      const bytes = new Uint8Array(await pageBlob.arrayBuffer());
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      setPreviewPdfBytes(bytes);
      setPreviewPage(newPage);
    } catch (err) {
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      const isFatal =
        err instanceof ApiError &&
        (err.status === 401 || err.status === 403 || err.errorCode === 'SESSION_TERMINATED');
      if (isFatal || (err instanceof Error && err.message === 'INVALID_PDF_MAGIC_BYTES')) {
        handleClosePreview(false);
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Không thể tải trang tài liệu. Vui lòng thử lại.'
            : 'Dữ liệu trang tài liệu không hợp lệ nên phiên xem đã được đóng.',
        );
      } else {
        setPreviewPageError(
          err instanceof ApiError
            ? err.message || `Không thể tải trang ${newPage}.`
            : `Không thể tải trang ${newPage}. Vui lòng thử lại.`,
        );
      }
    } finally {
      if (previewReqIdRef.current === reqId) {
        setIsLoadingPreview(false);
      }
    }
  }

  async function handleDownloadWithTicket(doc: DocumentItem) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này chỉ được phép xem trực tuyến theo mức độ mật hiện hành.');
      return;
    }

    setDownloadingDocId(doc.id);
    setErrorMessage(null);

    let downloadSessionId: string | null = null;
    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'DOWNLOAD' }),
        },
      );
      downloadSessionId = sessionResult.sessionId;

      const blob = await apiDownload(`/documents/${doc.id}/download`, {
        headers: { 'x-access-session-id': sessionResult.sessionId },
      });
      triggerBlobDownload(blob, resolveSafeDownloadFilename(blob, doc.documentCode, blob.filename));

      setMessage('Đã tải bản sao tài liệu thành công.');
    } catch (err) {
      if (downloadSessionId) {
        endAccessSessionFireAndForget(downloadSessionId);
      }
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
    previewVersionNo,
    previewPdfBytes,
    previewPdfUrl: null as string | null,
    previewPage,
    previewTotalPages,
    previewPageError,
    isLoadingPreview,
    downloadingDocId,
    handleClosePreview,
    handleOpenPreview,
    handlePageChange,
    handleRetryPage: () => handlePageChange(previewPage),
    handleDownloadWithTicket,
  };
}
