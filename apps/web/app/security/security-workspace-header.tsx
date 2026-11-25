'use client';

import { AlertTriangle, CheckCircle2, FileCheck, RefreshCw } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

interface SecurityWorkspaceHeaderProps {
  isLoading: boolean;
  message: string | null;
  errorMessage: string | null;
  canCreateIncident?: boolean;
  onRefresh: () => void;
  onOpenCreateIncident: () => void;
}

/**
 * Thuật toán: Thanh tiêu đề & Biểu ngữ trạng thái Trung tâm Giám sát An ninh SOC (`SecurityWorkspaceHeader`)
 * Mục đích: Hiển thị định danh phân hệ Security Officer, nút làm mới dữ liệu / lập báo cáo sự cố (nếu có quyền `INCIDENT_REPORT:CREATE`) và cảnh báo phản hồi từ API.
 */
export function SecurityWorkspaceHeader({
  isLoading,
  message,
  errorMessage,
  canCreateIncident = true,
  onRefresh,
  onOpenCreateIncident,
}: SecurityWorkspaceHeaderProps) {
  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="min-w-0">
          <Badge variant="destructive">Cán bộ an ninh thông tin</Badge>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-1">
            Giám sát an ninh và điều tra sự cố
          </h1>
        </div>

        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
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
          {canCreateIncident && (
            <InteractiveHoverButton
              variant="primary"
              size="sm"
              text="Tạo hồ sơ sự cố"
              icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={onOpenCreateIncident}
            />
          )}
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
