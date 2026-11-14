'use client';

import { SharedPdfPreviewModal } from '@/components/documents/shared-pdf-preview-modal';
import type { useReaderViewer } from '../hooks/use-reader-viewer';

interface DocumentViewerModalProps {
  viewer: ReturnType<typeof useReaderViewer>;
  userFullName?: string | null | undefined;
  username?: string | null | undefined;
}

export function DocumentViewerModal({ viewer }: DocumentViewerModalProps) {
  const {
    previewOpen,
    previewDoc,
    previewSessionId,
    previewPdfUrl,
    previewPage,
    previewTotalPages,
    isLoadingPreview,
    handleClosePreview,
    handlePageChange,
  } = viewer;

  return (
    <SharedPdfPreviewModal
      open={previewOpen}
      onOpenChange={handleClosePreview}
      title={previewDoc?.title}
      classificationCode={previewDoc?.classificationCode}
      sessionId={previewSessionId}
      pdfUrl={previewPdfUrl}
      page={previewPage}
      totalPages={previewTotalPages}
      isLoading={isLoadingPreview}
      pipelineLabel="Pipeline Gotenberg: Office (.docx/.xlsx/.pptx) -> Watermarked PDF"
      loadingLabel="Đang chuyển đổi tệp Office sang PDF và đóng dấu Watermark…"
      onPageChange={(newPage) => void handlePageChange(newPage)}
    />
  );
}
