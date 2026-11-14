'use client';

import { useState } from 'react';
import { AlertTriangle, Camera, CheckCircle2, HardDrive, XCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { HealthStatusLabel, SystemHealthData } from '../types';

interface SystemHealthTabProps {
  healthData: SystemHealthData | null;
  onCaptureSnapshot: () => Promise<boolean>;
}

/**
 * Thuật toán: Ánh Xạ Màu Sắc Ngữ Nghĩa, Chỉ Số Bộ Nhớ Tiến Trình & Chụp Bản Ghi Sức Khỏe (`SystemHealthTab`)
 * Mục đích: Trình bày trung thực trạng thái API Gateway, PostgreSQL, Redis, Kho lưu trữ đối tượng S3/R2, bộ nhớ `Heap / RSS` và lưu snapshot qua `POST /health/snapshots`.
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
  if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export function SystemHealthTab({ healthData, onCaptureSnapshot }: SystemHealthTabProps) {
  const [isCapturing, setIsCapturing] = useState(false);

  const gatewayStatus: HealthStatusLabel = healthData?.status ?? 'OFFLINE';
  const dbStatus: HealthStatusLabel = healthData?.database?.status ?? 'OFFLINE';
  const cacheStatus: HealthStatusLabel = healthData?.cache?.status ?? 'OFFLINE';
  const storageStatus: HealthStatusLabel = healthData?.storage?.status ?? 'OFFLINE';

  const gatewayTheme = resolveStatusTheme(gatewayStatus);
  const dbTheme = resolveStatusTheme(dbStatus);
  const cacheTheme = resolveStatusTheme(cacheStatus);
  const storageTheme = resolveStatusTheme(storageStatus);

  const GatewayIcon = gatewayTheme.Icon;
  const DbIcon = dbTheme.Icon;
  const CacheIcon = cacheTheme.Icon;
  const StorageIcon = storageTheme.Icon;

  const heapUsed = healthData?.memory?.heapUsedMb;
  const heapTotal = healthData?.memory?.heapTotalMb;
  const rssMb = healthData?.memory?.rssMb;

  async function handleCapture() {
    setIsCapturing(true);
    try {
      await onCaptureSnapshot();
    } finally {
      setIsCapturing(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
        <div>
          <h3 className="text-base font-semibold text-[#222222]">
            Giám sát sức khỏe hạ tầng &amp; Tiến trình vận hành
          </h3>
          <p className="text-xs text-[#717171]">
            Thăm dò thời gian thực API Gateway, PostgreSQL, Redis, Object Storage (S3 / R2) và bộ
            nhớ Node.js
          </p>
        </div>
        <InteractiveHoverButton
          variant="primary"
          size="sm"
          text="Chụp bản ghi sức khỏe"
          icon={<Camera size={16} strokeWidth={1.75} aria-hidden="true" />}
          isLoading={isCapturing}
          disabled={isCapturing}
          onClick={() => void handleCapture()}
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs text-[#717171]">
              Trạng thái API Gateway
            </CardDescription>
            <CardTitle
              className={`text-xl font-bold flex items-center gap-2 ${gatewayTheme.textClass}`}
            >
              <GatewayIcon
                size={20}
                strokeWidth={1.75}
                className={gatewayTheme.iconClass}
                aria-hidden="true"
              />
              <span>{gatewayStatus}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            {gatewayStatus === 'ONLINE'
              ? 'Zero-trust policy gates: Active'
              : 'Cảnh báo kết nối dịch vụ hạ tầng'}
          </CardContent>
        </Card>

        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs text-[#717171]">PostgreSQL Cluster</CardDescription>
            <CardTitle className={`text-xl font-bold flex items-center gap-2 ${dbTheme.textClass}`}>
              <DbIcon
                size={20}
                strokeWidth={1.75}
                className={dbTheme.iconClass}
                aria-hidden="true"
              />
              <span>{dbStatus}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            Độ trễ:{' '}
            {healthData?.database?.latencyMs !== undefined
              ? `${healthData.database.latencyMs}ms`
              : '—'}
          </CardContent>
        </Card>

        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs text-[#717171]">
              Bộ nhớ đệm phiên &amp; Chính sách (Redis)
            </CardDescription>
            <CardTitle
              className={`text-xl font-bold flex items-center gap-2 ${cacheTheme.textClass}`}
            >
              <CacheIcon
                size={20}
                strokeWidth={1.75}
                className={cacheTheme.iconClass}
                aria-hidden="true"
              />
              <span>{cacheStatus}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            {healthData?.cache?.latencyMs !== undefined
              ? `Độ trễ: ${healthData.cache.latencyMs}ms`
              : cacheStatus === 'ONLINE'
                ? 'Đồng bộ PDP & Rate-limit: Sẵn sàng'
                : 'Kết nối bộ đệm gián đoạn'}
          </CardContent>
        </Card>

        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs text-[#717171] flex items-center gap-1.5">
              <HardDrive
                size={16}
                strokeWidth={1.75}
                className="text-[#717171]"
                aria-hidden="true"
              />
              <span>Kho lưu trữ đối tượng (S3 / R2)</span>
            </CardDescription>
            <CardTitle
              className={`text-xl font-bold flex items-center gap-2 ${storageTheme.textClass}`}
            >
              <StorageIcon
                size={20}
                strokeWidth={1.75}
                className={storageTheme.iconClass}
                aria-hidden="true"
              />
              <span>{storageStatus}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171]">
            Độ trễ:{' '}
            {healthData?.storage?.latencyMs !== undefined
              ? `${healthData.storage.latencyMs}ms`
              : '—'}
          </CardContent>
        </Card>

        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs text-[#717171]">
              Uptime &amp; Bộ nhớ (Heap / RSS)
            </CardDescription>
            <CardTitle className="text-xl font-bold text-[#222222]">
              {formatUptimeDuration(healthData?.uptimeSeconds)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-[#717171] space-y-0.5">
            <div>
              Heap:{' '}
              <span className="font-semibold text-[#222222]">
                {heapUsed !== undefined && heapTotal !== undefined
                  ? `${heapUsed} / ${heapTotal} MB`
                  : '—'}
              </span>
            </div>
            <div>
              RSS:{' '}
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
