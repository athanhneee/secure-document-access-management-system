'use client';

import { useState } from 'react';
import { AlertTriangle, Camera, CheckCircle2, HardDrive, RefreshCw, XCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatServiceHealthLabel } from '@/lib/ui-labels';
import type { HealthStatusLabel, SystemHealthData } from '../types';

interface SystemHealthTabProps {
  healthData: SystemHealthData | null;
  healthFetchError?: string | null | undefined;
  isLoading?: boolean | undefined;
  onRetry?: (() => void) | undefined;
  onCaptureSnapshot: () => Promise<boolean>;
  canManageHealth?: boolean;
}

/**
 * Thuật toán: Ánh Xạ Màu Sắc Ngữ Nghĩa, Tách Biệt Lỗi Kết Nối Khỏi Suy Giảm Dịch Vụ `503` & Chụp Bản Ghi Sức Khỏe (`SystemHealthTab`, BUG-091)
 * Mục đích: Trình bày trung thực trạng thái API Gateway, PostgreSQL, Redis, Kho lưu trữ đối tượng S3/R2, bộ nhớ `Heap / RSS`,
 * và hiển thị thẻ lỗi kết nối kèm nút thử lại khi trình duyệt rớt mạng thay vì bịa đặt trạng thái `OFFLINE` giả.
 */
function resolveStatusTheme(status: HealthStatusLabel) {
  if (status === 'ONLINE') {
    return { textClass: 'text-[#008A05]', iconClass: 'text-[#008A05]', Icon: CheckCircle2 };
  }
  if (status === 'DEGRADED') {
    return { textClass: 'text-[#222222]', iconClass: 'text-[#E07912]', Icon: AlertTriangle };
  }
  return { textClass: 'text-[#C13515]', iconClass: 'text-[#C13515]', Icon: XCircle };
}

function formatUptimeDuration(seconds: number | undefined): string {
  if (seconds === undefined || seconds <= 0) return '—';
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (hrs > 0) return `${hrs} giờ ${mins} phút ${secs} giây`;
  if (mins > 0) return `${mins} phút ${secs} giây`;
  return `${secs} giây`;
}

export function SystemHealthTab({
  healthData,
  healthFetchError = null,
  isLoading = false,
  onRetry,
  onCaptureSnapshot,
  canManageHealth = true,
}: SystemHealthTabProps) {
  const [isCapturing, setIsCapturing] = useState(false);

  async function handleCapture() {
    if (!healthData || healthFetchError) return;
    setIsCapturing(true);
    try {
      await onCaptureSnapshot();
    } finally {
      setIsCapturing(false);
    }
  }

  if (!healthData) {
    return (
      <div className="space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4">
          <div className="min-w-0">
            <h3 className="text-sm sm:text-base font-semibold text-[#222222]">
              Tình trạng dịch vụ và tài nguyên
            </h3>
          </div>
          {canManageHealth && (
            <InteractiveHoverButton
              variant="primary"
              size="sm"
              text="Lưu bản ghi tình trạng"
              icon={<Camera size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled
              className="shrink-0"
            />
          )}
        </div>

        <Card>
          <CardContent className="py-10 px-4 text-center space-y-3">
            {isLoading && !healthFetchError ? (
              <div className="flex flex-col items-center gap-2 text-xs text-[#717171]">
                <RefreshCw
                  size={20}
                  strokeWidth={1.75}
                  className="animate-spin text-[#FF385C]"
                  aria-hidden="true"
                />
                <span>Đang kiểm tra tình trạng các dịch vụ hệ thống…</span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2.5 max-w-md mx-auto">
                <AlertTriangle
                  size={24}
                  strokeWidth={1.75}
                  className="text-[#C13515]"
                  aria-hidden="true"
                />
                <p className="text-sm font-semibold text-[#222222]">
                  Không thể tải thông tin tình trạng hệ thống
                </p>
                <p className="text-xs text-[#717171] leading-relaxed">
                  {healthFetchError ||
                    'Kết nối tới điểm cuối giám sát bị gián đoạn nên chưa thể xác định trạng thái thực tế của dịch vụ.'}
                </p>
                {onRetry && (
                  <InteractiveHoverButton
                    type="button"
                    variant="secondary"
                    size="sm"
                    text="Thử lại"
                    icon={
                      <RefreshCw
                        size={16}
                        strokeWidth={1.75}
                        className={isLoading ? 'animate-spin' : ''}
                        aria-hidden="true"
                      />
                    }
                    disabled={isLoading}
                    onClick={onRetry}
                  />
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  const gatewayStatus: HealthStatusLabel = healthData.status;
  const dbStatus: HealthStatusLabel = healthData.database.status;
  const cacheStatus: HealthStatusLabel = healthData.cache.status;
  const storageStatus: HealthStatusLabel = healthData.storage.status;

  const gatewayTheme = resolveStatusTheme(gatewayStatus);
  const dbTheme = resolveStatusTheme(dbStatus);
  const cacheTheme = resolveStatusTheme(cacheStatus);
  const storageTheme = resolveStatusTheme(storageStatus);

  const GatewayIcon = gatewayTheme.Icon;
  const DbIcon = dbTheme.Icon;
  const CacheIcon = cacheTheme.Icon;
  const StorageIcon = storageTheme.Icon;

  const heapUsed = healthData.memory?.heapUsedMb;
  const heapTotal = healthData.memory?.heapTotalMb;
  const rssMb = healthData.memory?.rssMb;

  return (
    <div className="space-y-3.5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4">
        <div className="min-w-0">
          <h3 className="text-sm sm:text-base font-semibold text-[#222222]">
            Tình trạng dịch vụ và tài nguyên
          </h3>
        </div>
        {canManageHealth && (
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text="Lưu bản ghi tình trạng"
            icon={<Camera size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={isCapturing}
            disabled={isCapturing || Boolean(healthFetchError)}
            onClick={() => void handleCapture()}
            className="shrink-0"
          />
        )}
      </div>

      <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        <Card>
          <CardHeader className="pb-1.5">
            <CardDescription className="text-xs text-[#717171]">Cổng dịch vụ</CardDescription>
            <CardTitle
              className={`text-sm font-bold flex items-center gap-1.5 ${gatewayTheme.textClass}`}
            >
              <GatewayIcon
                size={20}
                strokeWidth={1.75}
                className={`shrink-0 ${gatewayTheme.iconClass}`}
                aria-hidden="true"
              />
              <span>{formatServiceHealthLabel(gatewayStatus)}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            {gatewayStatus === 'ONLINE'
              ? 'Dịch vụ kiểm soát truy cập sẵn sàng'
              : 'Cảnh báo kết nối dịch vụ'}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-1.5">
            <CardDescription className="text-xs text-[#717171]">Cơ sở dữ liệu</CardDescription>
            <CardTitle
              className={`text-sm font-bold flex items-center gap-1.5 ${dbTheme.textClass}`}
            >
              <DbIcon
                size={20}
                strokeWidth={1.75}
                className={`shrink-0 ${dbTheme.iconClass}`}
                aria-hidden="true"
              />
              <span>{formatServiceHealthLabel(dbStatus)}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            Độ trễ:{' '}
            {healthData.database.latencyMs !== undefined
              ? `${healthData.database.latencyMs}ms`
              : '—'}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-1.5">
            <CardDescription className="text-xs text-[#717171]">Bộ nhớ đệm phiên</CardDescription>
            <CardTitle
              className={`text-sm font-bold flex items-center gap-1.5 ${cacheTheme.textClass}`}
            >
              <CacheIcon
                size={20}
                strokeWidth={1.75}
                className={`shrink-0 ${cacheTheme.iconClass}`}
                aria-hidden="true"
              />
              <span>{formatServiceHealthLabel(cacheStatus)}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            {healthData.cache.latencyMs !== undefined
              ? `Độ trễ: ${healthData.cache.latencyMs}ms`
              : cacheStatus === 'ONLINE'
                ? 'Quản lý phiên và giới hạn truy cập sẵn sàng'
                : 'Bộ nhớ đệm gián đoạn'}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-1.5">
            <CardDescription className="text-xs text-[#717171] flex items-center gap-1.5">
              <HardDrive
                size={16}
                strokeWidth={1.75}
                className="text-[#717171] shrink-0"
                aria-hidden="true"
              />
              <span>Kho lưu trữ tệp</span>
            </CardDescription>
            <CardTitle
              className={`text-sm font-bold flex items-center gap-1.5 ${storageTheme.textClass}`}
            >
              <StorageIcon
                size={20}
                strokeWidth={1.75}
                className={`shrink-0 ${storageTheme.iconClass}`}
                aria-hidden="true"
              />
              <span>{formatServiceHealthLabel(storageStatus)}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            Độ trễ:{' '}
            {healthData.storage.latencyMs !== undefined ? `${healthData.storage.latencyMs}ms` : '—'}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-1.5">
            <CardDescription className="text-xs text-[#717171]">
              Thời gian hoạt động &amp; Bộ nhớ
            </CardDescription>
            <CardTitle className="text-base font-bold text-[#222222]">
              {formatUptimeDuration(healthData.uptimeSeconds)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171] space-y-0.5">
            <div>
              Bộ nhớ ứng dụng:{' '}
              <span className="font-semibold text-[#222222]">
                {heapUsed !== undefined && heapTotal !== undefined
                  ? `${heapUsed} / ${heapTotal} MB`
                  : '—'}
              </span>
            </div>
            <div>
              Tổng bộ nhớ tiến trình:{' '}
              <span className="font-semibold text-[#222222]">
                {rssMb !== undefined ? `${rssMb} MB` : '—'}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
