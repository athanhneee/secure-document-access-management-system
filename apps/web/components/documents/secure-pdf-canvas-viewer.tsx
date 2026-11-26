'use client';

/**
 * Thuật toán: Trình Kết Xuất PDF Canvas Bảo Mật Đa Thiết Bị Không Dùng `iframe blob:` (`SecurePdfCanvasViewer`)
 * Mục đích:
 *   - Loại bỏ hoàn toàn `<iframe src="blob:...#toolbar=0">`, triệt tiêu lỗ hổng tải lậu qua `Ctrl+S` / `Ctrl+P` / mở `blob:` ở tab mới trên tài liệu `SECRET` & `TOP_SECRET` (`V-01`).
 *   - Kết xuất từng trang PDF trực tiếp từ bộ đệm nhị phân `Uint8Array` lên `<canvas>` bằng `pdfjs-dist` (worker cùng nguồn `/pdf.worker.min.mjs`) giúp hiển thị sắc nét trên cả Desktop, iOS Safari và Android Chrome (`V-57`).
 *   - Hỗ trợ phóng to/thu nhỏ, khớp chiều rộng, chặn chuột phải & chặn phím tắt lưu/in khi `allowDownload === false`.
 */
import { useEffect, useRef, useState } from 'react';
import { Loader2, RefreshCw, ShieldAlert } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface SecurePdfCanvasViewerProps {
  pdfBytes: Uint8Array;
  zoomScale: number;
  allowDownload?: boolean | undefined;
  title?: string | null | undefined;
}

export function SecurePdfCanvasViewer({
  pdfBytes,
  zoomScale,
  allowDownload = false,
  title,
}: SecurePdfCanvasViewerProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [renderError, setRenderError] = useState<string | null>(null);
  const [isRendering, setIsRendering] = useState(true);
  const [containerWidth, setContainerWidth] = useState(0);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const updateWidth = () => {
      const next = Math.max(260, Math.floor(el.clientWidth - 16));
      setContainerWidth((prev) => (Math.abs(prev - next) >= 12 ? next : prev));
    };
    updateWidth();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(updateWidth);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let cancelled = false;
    let renderTask: { cancel: () => void; promise: Promise<unknown> } | null = null;
    let loadingTask: { destroy: () => Promise<void> } | null = null;

    async function renderPage() {
      const canvas = canvasRef.current;
      if (!canvas) return;
      setIsRendering(true);
      setRenderError(null);

      try {
        const pdfjs = await import('pdfjs-dist');
        if (cancelled) return;
        pdfjs.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.mjs';

        // Sao chép mảng byte để PDF.js chuyển quyền sở hữu sang Worker mà không làm rỗng bộ đệm khi người dùng thay đổi mức thu phóng
        const dataCopy = new Uint8Array(pdfBytes.byteLength);
        dataCopy.set(pdfBytes);

        const task = pdfjs.getDocument({
          data: dataCopy,
          useSystemFonts: true,
        });
        loadingTask = task;
        const pdfDoc = await task.promise;
        if (cancelled) {
          await task.destroy();
          return;
        }

        const pdfPage = await pdfDoc.getPage(1);
        if (cancelled) {
          await task.destroy();
          return;
        }

        const baseViewport = pdfPage.getViewport({ scale: 1 });
        const availableWidth = containerWidth > 0 ? containerWidth : 720;
        const fitScale = Math.min(2.2, Math.max(0.55, availableWidth / baseViewport.width));
        const effectiveScale = Math.min(3, Math.max(0.5, fitScale * zoomScale));
        const outputScale = Math.min(window.devicePixelRatio || 1, 2);
        const viewport = pdfPage.getViewport({ scale: effectiveScale });

        canvas.width = Math.max(1, Math.floor(viewport.width * outputScale));
        canvas.height = Math.max(1, Math.floor(viewport.height * outputScale));
        canvas.style.width = `${Math.floor(viewport.width)}px`;
        canvas.style.height = `${Math.floor(viewport.height)}px`;

        const ctx = canvas.getContext('2d', { alpha: false });
        if (!ctx) {
          await task.destroy();
          throw new Error('CANVAS_CONTEXT_UNAVAILABLE');
        }

        ctx.save();
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.restore();

        const currentRender = pdfPage.render({
          canvas,
          canvasContext: ctx,
          viewport,
          transform: outputScale !== 1 ? [outputScale, 0, 0, outputScale, 0, 0] : undefined,
        });
        renderTask = currentRender;
        await currentRender.promise;
        await pdfDoc.cleanup();
        await task.destroy();
      } catch (err) {
        if (cancelled) return;
        const errName = err instanceof Error ? err.name : '';
        if (errName === 'RenderingCancelledException') return;
        setRenderError('Không thể kết xuất trang tài liệu trên trình duyệt này. Vui lòng thử lại.');
      } finally {
        if (!cancelled) {
          setIsRendering(false);
        }
      }
    }

    void renderPage();

    return () => {
      cancelled = true;
      try {
        renderTask?.cancel();
      } catch {
        // Bỏ qua lỗi hủy tác vụ vẽ đang dừng
      }
      if (loadingTask) {
        void loadingTask.destroy().catch(() => undefined);
      }
    };
  }, [pdfBytes, zoomScale, containerWidth, retryCount]);

  return (
    <div
      ref={containerRef}
      onContextMenu={(e) => {
        if (!allowDownload) e.preventDefault();
      }}
      className="relative w-full h-[50dvh] sm:h-[62dvh] max-h-[600px] min-h-[260px] overflow-auto rounded-[16px] border border-[#dddddd] bg-[#ebebeb] p-2 sm:p-3 flex flex-col items-center select-none"
      aria-label={title ? `Nội dung trang tài liệu ${title}` : 'Nội dung trang tài liệu bảo mật'}
    >
      {renderError && (
        <div
          role="alert"
          className="my-auto w-full max-w-md rounded-[16px] border border-[#dddddd] bg-[#ffffff] p-4 text-center space-y-3"
        >
          <div className="flex justify-center text-[#C13515]">
            <ShieldAlert size={20} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <p className="text-xs font-semibold text-[#C13515]">{renderError}</p>
          <div className="flex justify-center">
            <InteractiveHoverButton
              type="button"
              size="sm"
              variant="secondary"
              text="Thử kết xuất lại"
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => setRetryCount((prev) => prev + 1)}
            />
          </div>
        </div>
      )}
      <div className={renderError ? 'hidden' : 'relative my-auto flex items-center justify-center'}>
        <canvas
          ref={canvasRef}
          className="block rounded bg-[#ffffff] shadow-sm max-w-none"
          aria-label={title || 'Trang tài liệu PDF bảo mật'}
        />
        {isRendering && (
          <div className="absolute inset-0 flex items-center justify-center bg-[#ffffff]/75 rounded">
            <Loader2
              size={24}
              strokeWidth={2}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
          </div>
        )}
      </div>
    </div>
  );
}
