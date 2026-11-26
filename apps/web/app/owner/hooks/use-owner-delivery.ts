'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { shouldOfferMfaActionForError } from '@/lib/api-error-messages';
import { useAuth } from '@/lib/auth-context';
import { getOrCreateDeviceFingerprint } from '@/lib/device-fingerprint';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
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
 * Thuật toán: Mở Hộp Thoại Xem Trước Canvas Sau Xác Thực Phiên Không Nháy Modal, Đính Kèm `deviceFingerprint`, Đồng Bộ Đóng Phiên SSE & Phản Hồi MFA (`useOwnerDelivery`)
 * Mục đích:
 *   - Phản hồi ngay `< 16ms` trên nút bấm qua `openingDocId`, đính kèm `deviceFingerprint`, chỉ mở khung xem trước sau khi PEP phê duyệt phiên `VIEW` (tránh nháy đóng sập modal khi nhận `403`).
 *   - Tính giao quyền tải thực tế theo phiên (`sessionResult.allowDownload && hasPermission('DOCUMENT:DOWNLOAD') && !obligations.includes('FORBID_DOWNLOAD')`) không mutate đối tượng bảng nền, lắng nghe SSE `ACCESS_SESSION_UPDATED` gọi `closePreviewLocally(false)` không bắn lặp `/end`, lưu `failedPage` khi thử lại trang và quản lý tải song song qua `downloadingDocIds: ReadonlySet<string>`.
 */
export function useOwnerDelivery({ setMessage, setErrorMessage }: UseOwnerDeliveryParams) {
  const { hasPermission } = useAuth();
  const [previewOpen, setPreviewOpen] = useState(false);
  const [openingDocId, setOpeningDocId] = useState<string | null>(null);
  const [previewDoc, setPreviewDoc] = useState<DocumentItem | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewVersionNo, setPreviewVersionNo] = useState<number | null>(null);
  const [previewAllowDownload, setPreviewAllowDownload] = useState(false);
  const [previewObligations, setPreviewObligations] = useState<readonly string[]>([]);
  const [previewPdfBytes, setPreviewPdfBytes] = useState<Uint8Array | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const [failedPage, setFailedPage] = useState<number | null>(null);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [previewPageError, setPreviewPageError] = useState<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [mfaActionRequired, setMfaActionRequired] = useState(false);
  const [downloadingDocIds, setDownloadingDocIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  );
  const previewReqIdRef = useRef(0);
  const previewAbortRef = useRef<AbortController | null>(null);
  const activeSessionIdRef = useRef<string | null>(null);
  const previewDocRef = useRef<DocumentItem | null>(null);
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
      previewAbortRef.current?.abort();
      previewAbortRef.current = null;
      if (activeSessionIdRef.current) {
        endAccessSessionFireAndForget(activeSessionIdRef.current);
        activeSessionIdRef.current = null;
      }
    };
  }, []);

  const closePreviewLocally = useCallback((notifyServer: boolean) => {
    previewReqIdRef.current += 1;
    previewAbortRef.current?.abort();
    previewAbortRef.current = null;
    setOpeningDocId(null);
    setIsLoadingPreview(false);
    setPreviewOpen(false);
    setPreviewPdfBytes(null);
    setPreviewPageError(null);
    setFailedPage(null);
    setPreviewAllowDownload(false);
    setPreviewObligations([]);
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

  useEffect(() => {
    const unsubSession = subscribeRealtimeEvent<{
      id?: string;
      sessionId?: string;
      documentId?: string;
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
      const matchedByDoc = Boolean(
        currentDoc && !p.sessionId && !p.id && p.documentId && p.documentId === currentDoc.id,
      );
      if (!matchedBySession && !matchedByDoc) return;
      closePreviewLocally(false);
      setMessage(null);
      setErrorMessage(
        'Phiên xem tài liệu đang mở đã bị chấm dứt bởi chính sách an ninh hoặc thao tác lưu trữ.',
      );
    });

    return () => {
      unsubSession();
    };
  }, [closePreviewLocally, setErrorMessage, setMessage]);

  async function handleOpenPreview(doc: DocumentItem) {
    previewAbortRef.current?.abort();
    const controller = new AbortController();
    previewAbortRef.current = controller;

    if (activeSessionIdRef.current) {
      endAccessSessionFireAndForget(activeSessionIdRef.current);
      activeSessionIdRef.current = null;
    }
    const reqId = ++previewReqIdRef.current;
    setOpeningDocId(doc.id);
    setPreviewPdfBytes(null);
    setPreviewPageError(null);
    setFailedPage(null);
    setPreviewAllowDownload(false);
    setPreviewObligations([]);
    setMfaActionRequired(false);
    setErrorMessage(null);
    setPreviewDoc(doc);
    setPreviewSessionId(null);
    setPreviewVersionNo(null);
    setPreviewPage(1);
    setPreviewTotalPages(1);
    setIsLoadingPreview(true);

    try {
      const deviceFingerprint = getOrCreateDeviceFingerprint();
      const sessionPayload: { action: 'VIEW'; deviceFingerprint?: string } = { action: 'VIEW' };
      if (deviceFingerprint) {
        sessionPayload.deviceFingerprint = deviceFingerprint;
      }

      const sessionResult = await apiClient<{
        sessionId: string;
        versionNo?: number;
        allowDownload?: boolean;
        obligations?: string[];
      }>(`/documents/${doc.id}/sessions`, {
        method: 'POST',
        body: JSON.stringify(sessionPayload),
        signal: controller.signal,
      });

      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        endAccessSessionFireAndForget(sessionResult.sessionId);
        return;
      }

      const obligations = Array.isArray(sessionResult.obligations) ? sessionResult.obligations : [];
      const sessionAllowDownload = sessionResult.allowDownload === true;
      const effectiveAllowDownload =
        sessionAllowDownload &&
        Boolean(doc.allowDownload) &&
        hasPermission('DOCUMENT:DOWNLOAD') &&
        !obligations.includes('FORBID_DOWNLOAD');

      activeSessionIdRef.current = sessionResult.sessionId;
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewVersionNo(
        typeof sessionResult.versionNo === 'number' ? sessionResult.versionNo : null,
      );
      setPreviewObligations(obligations);
      setPreviewAllowDownload(effectiveAllowDownload);
      setOpeningDocId(null);
      setPreviewOpen(true);

      const pdfBlob = await apiDownload(`/documents/${doc.id}/preview/page/1`, {
        headers: { 'x-access-session-id': sessionResult.sessionId },
        signal: controller.signal,
      });
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      if (!(await verifyPdfMagicBytes(pdfBlob))) {
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      const bytes = new Uint8Array(await pdfBlob.arrayBuffer());
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      setPreviewTotalPages(pdfBlob.totalPages && pdfBlob.totalPages > 0 ? pdfBlob.totalPages : 1);
      setPreviewPdfBytes(bytes);
    } catch (err) {
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      closePreviewLocally(true);
      if (err instanceof ApiError) {
        if (shouldOfferMfaActionForError(err.errorCode, err.response?.details)) {
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
        setOpeningDocId(null);
        setIsLoadingPreview(false);
      }
    }
  }

  async function handlePageChange(newPage: number) {
    if (!previewDoc || !previewSessionId || newPage < 1 || newPage > previewTotalPages) return;
    previewAbortRef.current?.abort();
    const controller = new AbortController();
    previewAbortRef.current = controller;

    const reqId = ++previewReqIdRef.current;
    setIsLoadingPreview(true);
    setPreviewPageError(null);
    setMfaActionRequired(false);
    try {
      const pageBlob = await apiDownload(`/documents/${previewDoc.id}/preview/page/${newPage}`, {
        headers: { 'x-access-session-id': previewSessionId },
        signal: controller.signal,
      });
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      if (!(await verifyPdfMagicBytes(pageBlob))) {
        throw new Error('INVALID_PDF_MAGIC_BYTES');
      }
      const bytes = new Uint8Array(await pageBlob.arrayBuffer());
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      setFailedPage(null);
      setPreviewPdfBytes(bytes);
      setPreviewPage(newPage);
    } catch (err) {
      if (previewReqIdRef.current !== reqId || controller.signal.aborted) {
        return;
      }
      if (
        err instanceof ApiError &&
        shouldOfferMfaActionForError(err.errorCode, err.response?.details)
      ) {
        setMfaActionRequired(true);
      }
      const isFatal =
        err instanceof ApiError &&
        (err.status === 401 ||
          err.status === 403 ||
          err.errorCode === 'SESSION_TERMINATED' ||
          err.errorCode === 'SESSION_EXPIRED' ||
          err.errorCode === 'GRANT_REVOKED' ||
          err.errorCode === 'GRANT_EXPIRED');
      if (isFatal || (err instanceof Error && err.message === 'INVALID_PDF_MAGIC_BYTES')) {
        closePreviewLocally(false);
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Không thể tải trang tài liệu. Vui lòng thử lại.'
            : 'Dữ liệu trang tài liệu không hợp lệ nên phiên xem đã được đóng.',
        );
      } else {
        setFailedPage(newPage);
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

  async function handleRetryPage() {
    await handlePageChange(failedPage ?? previewPage);
  }

  async function handleDownloadWithTicket(doc: DocumentItem) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này chỉ được phép xem trực tuyến theo mức độ mật hiện hành.');
      return;
    }

    setDownloadingDocIds((prev) => {
      const next = new Set(prev);
      next.add(doc.id);
      return next;
    });
    setErrorMessage(null);
    setMfaActionRequired(false);

    let downloadSessionId: string | null = null;
    try {
      const deviceFingerprint = getOrCreateDeviceFingerprint();
      const sessionPayload: { action: 'DOWNLOAD'; deviceFingerprint?: string } = {
        action: 'DOWNLOAD',
      };
      if (deviceFingerprint) {
        sessionPayload.deviceFingerprint = deviceFingerprint;
      }

      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify(sessionPayload),
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
        if (shouldOfferMfaActionForError(err.errorCode, err.response?.details)) {
          setMfaActionRequired(true);
        }
        setErrorMessage(err.message || 'Không thể tải tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo bản sao tải về.');
      }
    } finally {
      setDownloadingDocIds((prev) => {
        const next = new Set(prev);
        next.delete(doc.id);
        return next;
      });
    }
  }

  return {
    previewOpen,
    openingDocId,
    previewDoc,
    previewSessionId,
    previewVersionNo,
    previewAllowDownload,
    previewObligations,
    previewPdfBytes,
    previewPdfUrl: null as string | null,
    previewPage,
    failedPage,
    previewTotalPages,
    previewPageError,
    isLoadingPreview,
    mfaActionRequired,
    clearMfaActionRequired: () => setMfaActionRequired(false),
    downloadingDocIds,
    downloadingDocId: downloadingDocIds.values().next().value ?? null,
    closePreviewLocally,
    handleClosePreview,
    handleOpenPreview,
    handlePageChange,
    handleRetryPage,
    handleDownloadWithTicket,
  };
}
