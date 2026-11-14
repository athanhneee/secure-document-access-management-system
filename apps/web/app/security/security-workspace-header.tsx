'use client';

import { AlertTriangle, CheckCircle2, FileCheck, RefreshCw } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

interface SecurityWorkspaceHeaderProps {
  isLoading: boolean;
  message: string | null;
  errorMessage: string | null;
  onRefresh: () => void;
  onOpenCreateIncident: () => void;
}

/**
 * Thuật toán: Thanh tiêu đề & Biểu ngữ trạng thái Trung tâm Giám sát An ninh SOC (`SecurityWorkspaceHeader`)
 * Mục đích: Hiển thị định danh phân hệ Security Officer, nút làm mới dữ liệu / lập báo cáo sự cố và cảnh báo phản hồi từ API.
 */
export function SecurityWorkspaceHeader({
  isLoading,
  message,
  errorMessage,
  onRefresh,
  onOpenCreateIncident,
}: SecurityWorkspaceHeaderProps) {
  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Badge variant="destructive">Security Officer</Badge>
            <span className="text-xs text-[#717171]">Phân hệ An ninh Thông tin</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
            Giám sát An ninh &amp; Điều tra Sự cố
          </h1>
          <p className="text-xs text-[#717171]">
            Xử lý cảnh báo xâm phạm, điều tra provenance watermark, xử lý sự cố và luật phát hiện
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Làm mới"
            icon={
              <RefreshCw
                size={16}
                strokeWidth={1.75}
                className={isLoading ? 'animate-spin' : ''}
                aria-hidden="true"
              />
            }
            onClick={onRefresh}
            disabled={isLoading}
          />
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text="Lập báo cáo sự cố"
            icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onOpenCreateIncident}
          />
        </div>
      </div>

      {message && (
        <Alert variant="success" className="text-xs">
          <CheckCircle2
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#008A05]"
            aria-hidden="true"
          />
          <AlertDescription className="ml-2">{message}</AlertDescription>
        </Alert>
      )}

      {errorMessage && (
        <Alert variant="destructive" className="text-xs">
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#C13515]"
            aria-hidden="true"
          />
          <div className="ml-2 flex flex-wrap items-center justify-between gap-2">
            <AlertDescription>{errorMessage}</AlertDescription>
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              text="Thử lại"
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={onRefresh}
              disabled={isLoading}
            />
          </div>
        </Alert>
      )}
    </>
  );
}
