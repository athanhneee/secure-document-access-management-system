'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { triggerWatermarkedDownload } from '../helpers';
import type { MyGrantedDoc } from '../types';

interface UseReaderViewerParams {
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
 * Thuật toán: Mở Hộp Thoại Xem Trước Canvas Tức Thì Dưới 16ms, Đồng Bộ Đóng Phiên SSE & Chống Rò Rỉ URL (`useReaderViewer`)
 * Mục đích:
 *   - Mở ngay hộp thoại phương thức trước `await`, nạp duy nhất trang 1 (`/preview/page/1`) sang mảng byte `Uint8Array` (không tạo `blob:` URL cho trình xem — `V-01`, `V-04`, `V-57`) với mã phiên qua header `X-Access-Session-Id` (`V-12`).
 *   - Bảo vệ cả mở đầu lẫn chuyển trang bằng khóa tăng dần `previewReqIdRef` chống race condition (`V-07`), lắng nghe SSE `ACCESS_GRANT_UPDATED` / `ACCESS_SESSION_UPDATED` để đóng ngay tài liệu khi bị thu hồi quyền hoặc SOC ngắt phiên (`V-05`), và gọi `POST /access-sessions/:id/end` khi người xem đóng modal (`V-10`).
 *   - Tải xuống trực tiếp qua kênh xác thực `GET /documents/:id/download` kèm `X-Access-Session-Id` (không lộ vé trên URL — `V-02`), bảo toàn tên/đuôi tệp thật (`V-08`) và quản lý song song bằng `Set` `downloadingDocIds` (`V-42`).
 */
export function useReaderViewer({ setMessage, setErrorMessage }: UseReaderViewerParams) {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<MyGrantedDoc | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewVersionNo, setPreviewVersionNo] = useState<number | null>(null);
  const [previewPdfBytes, setPreviewPdfBytes] = useState<Uint8Array | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [previewPageError, setPreviewPageError] = useState<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [mfaActionRequired, setMfaActionRequired] = useState(false);
  const [downloadingDocIds, setDownloadingDocIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  );
  const previewReqIdRef = useRef(0);
  const activeSessionIdRef = useRef<string | null>(null);
  const previewDocRef = useRef<MyGrantedDoc | null>(null);
  const previewOpenRef = useRef(false);

  useEffect(() => {
    activeSessionIdRef.current = previewSessionId;
  }, [previewSessionId]);

  useEffect(() => {
    previewDocRef.current = previewDoc;
  }, [previewDoc]);

  useEffect(() => {
    previewOpenRef.current = previewOpen;
  }, [previewOpen]);

  useEffect(() => {
    return () => {
      if (activeSessionIdRef.current) {
        endAccessSessionFireAndForget(activeSessionIdRef.current);
        activeSessionIdRef.current = null;
      }
    };
  }, []);

  const closePreviewLocally = useCallback((notifyServer: boolean) => {
    previewReqIdRef.current += 1;
    setIsLoadingPreview(false);
    setPreviewOpen(false);
    setPreviewPdfBytes(null);
    setPreviewPageError(null);
    const sid = activeSessionIdRef.current;
    activeSessionIdRef.current = null;
    setPreviewSessionId(null);
    setPreviewVersionNo(null);
    if (notifyServer && sid) {
      endAccessSessionFireAndForget(sid);
    }
  }, []);

  const handleClosePreview = useCallback(
    (open: boolean) => {
      if (!open) {
        closePreviewLocally(true);
      } else {
        setPreviewOpen(true);
      }
    },
    [closePreviewLocally],
  );

  // Thuật toán: Tự động đóng ngay trình xem tài liệu khi nhận SSE thu hồi quyền hoặc ngắt phiên từ SOC/Chủ sở hữu (`V-05`, `V-24`).
  useEffect(() => {
    const unsubGrant = subscribeRealtimeEvent<{
      id?: string;
      documentId?: string;
      action?: string;
      status?: string;
    }>('ACCESS_GRANT_UPDATED', (event) => {
      if (!previewOpenRef.current) return;
      const p = event.payload;
      const isRevoked = p?.action === 'REVOKED' || p?.status === 'REVOKED';
      if (!isRevoked) return;
      const currentDoc = previewDocRef.current;
      if (
        !currentDoc ||
        (p.documentId && p.documentId !== currentDoc.documentId && p.id && p.id !== currentDoc.id)
      ) {
        return;
      }
      closePreviewLocally(false);
      setMessage(null);
      setErrorMessage(
        'Quyền truy cập đối với tài liệu đang mở vừa bị thu hồi. Phiên xem đã được đóng ngay lập tức.',
      );
    });

    const unsubSession = subscribeRealtimeEvent<{
      id?: string;
      sessionId?: string;
      documentId?: string;
      grantId?: string;
      status?: string;
      action?: string;
      terminatedSessionIds?: string[];
    }>('ACCESS_SESSION_UPDATED', (event) => {
      if (!previewOpenRef.current) return;
      const p = event.payload;
      const isTerminated =
        p?.status === 'TERMINATED' || p?.action === 'TERMINATED' || p?.action === 'GRANT_REVOKED';
      if (!isTerminated) return;
      const currentSid = activeSessionIdRef.current;
      const currentDoc = previewDocRef.current;
      const matchedBySession = Boolean(
        currentSid &&
        (p.sessionId === currentSid ||
          p.id === currentSid ||
          (Array.isArray(p.terminatedSessionIds) && p.terminatedSessionIds.includes(currentSid))),
      );
      const matchedByDocOrGrant = Boolean(
        currentDoc &&
        ((p.documentId && p.documentId === currentDoc.documentId) ||
          (p.grantId && p.grantId === currentDoc.id)),
      );
      if (!matchedBySession && !matchedByDocOrGrant) return;
      closePreviewLocally(false);
      setMessage(null);
      setErrorMessage(
        'Phiên xem tài liệu đang mở đã bị chấm dứt bởi chính sách an ninh hoặc do quyền truy cập bị thu hồi.',
      );
    });

    return () => {
      unsubGrant();
      unsubSession();
    };
  }, [closePreviewLocally, setErrorMessage, setMessage]);

  async function handleOpenPreview(doc: MyGrantedDoc) {
    const previousSid = activeSessionIdRef.current;
    if (previousSid) {
      endAccessSessionFireAndForget(previousSid);
      activeSessionIdRef.current = null;
    }

    const reqId = ++previewReqIdRef.current;
    setPreviewPdfBytes(null);
    setPreviewPageError(null);
    setMfaActionRequired(false);
    setErrorMessage(null);
    setPreviewDoc(doc);
    setPreviewSessionId(null);
    setPreviewVersionNo(null);
    setPreviewPage(1);
    setPreviewTotalPages(1);
    setIsLoadingPreview(true);
    setPreviewOpen(true);

    try {
      const sessionPayload: { action: 'VIEW'; grantId?: string } = { action: 'VIEW' };
      if (UUID_RE.test(doc.id)) {
        sessionPayload.grantId = doc.id;
      }

      const sessionResult = await apiClient<{
        sessionId: string;
        versionNo?: number;
      }>(`/documents/${doc.documentId}/sessions`, {
        method: 'POST',
        body: JSON.stringify(sessionPayload),
      });

      if (previewReqIdRef.current !== reqId) {
        endAccessSessionFireAndForget(sessionResult.sessionId);
        return;
      }

      activeSessionIdRef.current = sessionResult.sessionId;
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewVersionNo(
        typeof sessionResult.versionNo === 'number' ? sessionResult.versionNo : null,
      );

      // CONFLICT-RESOLVED: Nạp đúng trang 1 (/preview/page/1) qua header X-Access-Session-Id và kết xuất Canvas không tạo blob URL (V-01, V-04, V-12).
      const pdfBlob = await apiDownload(`/documents/${doc.documentId}/preview/page/1`, {
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
      closePreviewLocally(true);
      if (err instanceof ApiError) {
        if (err.errorCode === 'STEP_UP_MFA_REQUIRED') {
          setMfaActionRequired(true);
        }
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
    if (newPage < 1 || newPage > previewTotalPages || !previewDoc || !previewSessionId) return;
    const reqId = ++previewReqIdRef.current;
    setIsLoadingPreview(true);
    setPreviewPageError(null);
    try {
      const pdfBlob = await apiDownload(
        `/documents/${previewDoc.documentId}/preview/page/${newPage}`,
        {
          headers: { 'x-access-session-id': previewSessionId },
        },
      );
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
      setPreviewPage(newPage);
      setPreviewPdfBytes(bytes);
    } catch (err) {
      if (previewReqIdRef.current !== reqId) {
        return;
      }
      const isFatalSessionError =
        err instanceof ApiError &&
        (err.status === 401 ||
          err.status === 403 ||
          err.errorCode === 'SESSION_TERMINATED' ||
          err.errorCode === 'SESSION_EXPIRED' ||
          err.errorCode === 'GRANT_REVOKED' ||
          err.errorCode === 'GRANT_EXPIRED');

      if (
        isFatalSessionError ||
        (err instanceof Error && err.message === 'INVALID_PDF_MAGIC_BYTES')
      ) {
        closePreviewLocally(false);
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Phiên xem tài liệu đã kết thúc hoặc không còn hiệu lực.'
            : 'Dữ liệu trang tài liệu không hợp lệ nên phiên xem đã được đóng.',
        );
      } else {
        // Giữ nguyên hộp thoại xem trước khi lỗi mạng tạm thời khi chuyển trang (V-07)
        setPreviewPageError(
          err instanceof ApiError
            ? err.message || `Không thể tải trang ${newPage}. Vui lòng thử lại.`
            : `Không thể tải trang ${newPage}. Vui lòng kiểm tra kết nối và thử lại.`,
        );
      }
    } finally {
      if (previewReqIdRef.current === reqId) {
        setIsLoadingPreview(false);
      }
    }
  }

  async function handleRetryPage() {
    await handlePageChange(previewPage);
  }

  async function handleDownloadWithTicket(doc: MyGrantedDoc) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này chỉ được phép xem trực tuyến theo mức độ mật hiện hành.');
      return;
    }

    setDownloadingDocIds((prev) => {
      const next = new Set(prev);
      next.add(doc.documentId);
      return next;
    });
    setErrorMessage(null);
    setMfaActionRequired(false);

    let downloadSessionId: string | null = null;
    try {
      const sessionPayload: { action: 'DOWNLOAD'; grantId?: string } = { action: 'DOWNLOAD' };
      if (UUID_RE.test(doc.id)) {
        sessionPayload.grantId = doc.id;
      }

      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify(sessionPayload),
        },
      );
      downloadSessionId = sessionResult.sessionId;

      // CONFLICT-RESOLVED: Gọi trực tiếp endpoint xác thực GET /documents/:id/download kèm header X-Access-Session-Id thay vì lộ vé 256-bit DT-... trên URL path (V-02, V-12).
      const blob = await apiDownload(`/documents/${doc.documentId}/download`, {
        headers: { 'x-access-session-id': sessionResult.sessionId },
      });
      triggerWatermarkedDownload(blob, doc.documentCode, blob.filename);
      setMessage('Đã tải bản sao tài liệu thành công.');
    } catch (err) {
      if (downloadSessionId) {
        endAccessSessionFireAndForget(downloadSessionId);
      }
      if (err instanceof ApiError) {
        if (err.errorCode === 'STEP_UP_MFA_REQUIRED') {
          setMfaActionRequired(true);
        }
        setErrorMessage(err.message || 'Không thể tải tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo bản sao tải về.');
      }
    } finally {
      setDownloadingDocIds((prev) => {
        const next = new Set(prev);
        next.delete(doc.documentId);
        return next;
      });
    }
  }

  return {
    previewOpen,
    previewDoc,
    previewSessionId,
    previewVersionNo,
    previewPdfBytes,
    previewPage,
    previewTotalPages,
    previewPageError,
    isLoadingPreview,
    mfaActionRequired,
    clearMfaActionRequired: () => setMfaActionRequired(false),
    downloadingDocIds,
    downloadingDocId: downloadingDocIds.values().next().value ?? null,
    handleClosePreview,
    handleOpenPreview,
    handlePageChange,
    handleRetryPage,
    handleDownloadWithTicket,
  };
}
