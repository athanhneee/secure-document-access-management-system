'use client';

import { SharedPdfPreviewModal } from '@/components/documents/shared-pdf-preview-modal';
import type { useReaderViewer } from '../hooks/use-reader-viewer';

interface DocumentViewerModalProps {
  viewer: ReturnType<typeof useReaderViewer>;
}

/**
 * Thuật toán: Bọc Chuyển Tiếp Trạng Thái Xem Trước Canvas Bảo Mật Cho Người Đọc (`DocumentViewerModal`, V-51)
 */
export function DocumentViewerModal({ viewer }: DocumentViewerModalProps) {
  const {
    previewOpen,
    previewDoc,
    previewSessionId,
    previewPdfBytes,
    previewPage,
    previewTotalPages,
    previewVersionNo,
    previewPageError,
    isLoadingPreview,
    handleClosePreview,
    handlePageChange,
    handleRetryPage,
  } = viewer;

  return (
    <SharedPdfPreviewModal
      open={previewOpen}
      onOpenChange={handleClosePreview}
      title={previewDoc?.title}
      classificationCode={previewDoc?.classificationCode}
      sessionId={previewSessionId}
      pdfBytes={previewPdfBytes}
      page={previewPage}
      totalPages={previewTotalPages}
      versionNo={previewVersionNo}
      allowDownload={previewDoc?.allowDownload ?? false}
      pageError={previewPageError}
      onRetryPage={() => void handleRetryPage()}
      isLoading={isLoadingPreview}
      pipelineLabel="Chế độ xem bảo mật · Có gắn watermark bảo mật"
      loadingLabel="Đang chuẩn bị bản xem trước tài liệu và gắn watermark bảo mật…"
      onPageChange={(newPage) => void handlePageChange(newPage)}
    />
  );
}
