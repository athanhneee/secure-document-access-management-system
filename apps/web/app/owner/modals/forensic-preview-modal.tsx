'use client';

import { SharedPdfPreviewModal } from '@/components/documents/shared-pdf-preview-modal';
import type { DocumentItem } from '../types';

interface ForensicPreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  sessionId: string | null;
  pdfUrl: string | null;
  page: number;
  totalPages: number;
  isLoading: boolean;
  userFullName?: string | null | undefined;
  username?: string | null | undefined;
  onPageChange: (newPage: number) => void;
}

export function ForensicPreviewModal({
  open,
  onOpenChange,
  document,
  sessionId,
  pdfUrl,
  page,
  totalPages,
  isLoading,
  onPageChange,
}: ForensicPreviewModalProps) {
  return (
    <SharedPdfPreviewModal
      open={open}
      onOpenChange={onOpenChange}
      title={document?.title}
      classificationCode={document?.classificationCode}
      sessionId={sessionId}
      pdfUrl={pdfUrl}
      page={page}
      totalPages={totalPages}
      isLoading={isLoading}
      pipelineLabel="Pipeline Gotenberg: Office -> Watermarked PDF"
      loadingLabel="Đang xử lý trang tài liệu và nhúng dấu Watermark động…"
      onPageChange={onPageChange}
    />
  );
}
