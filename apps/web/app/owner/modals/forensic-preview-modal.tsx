'use client';

import { SharedPdfPreviewModal } from '@/components/documents/shared-pdf-preview-modal';
import type { DocumentItem } from '../types';

interface ForensicPreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  sessionId: string | null;
  versionNo?: number | null | undefined;
  allowDownload?: boolean | undefined;
  obligations?: readonly string[] | undefined;
  pdfBytes?: Uint8Array | null | undefined;
  pdfUrl?: string | null | undefined;
  page: number;
  totalPages: number;
  pageError?: string | null | undefined;
  isLoading: boolean;
  onPageChange: (newPage: number) => void;
  onRetryPage?: (() => void) | undefined;
}

export function ForensicPreviewModal({
  open,
  onOpenChange,
  document,
  sessionId,
  versionNo,
  allowDownload = false,
  obligations = [],
  pdfBytes,
  pdfUrl,
  page,
  totalPages,
  pageError,
  isLoading,
  onPageChange,
  onRetryPage,
}: ForensicPreviewModalProps) {
  return (
    <SharedPdfPreviewModal
      open={open}
      onOpenChange={onOpenChange}
      title={document?.title}
      classificationCode={document?.classificationCode}
      sessionId={sessionId}
      versionNo={versionNo}
      pdfBytes={pdfBytes}
      pdfUrl={pdfUrl}
      page={page}
      totalPages={totalPages}
      allowDownload={allowDownload}
      obligations={obligations}
      pageError={pageError}
      onRetryPage={onRetryPage}
      isLoading={isLoading}
      pipelineLabel="Chế độ xem bảo mật · Có gắn watermark bảo mật"
      loadingLabel="Đang chuẩn bị bản xem trước tài liệu và gắn watermark bảo mật…"
      onPageChange={onPageChange}
    />
  );
}
