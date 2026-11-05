'use client';

import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import type { HealthStatusLabel, SystemHealthData } from '../types';

interface SystemHealthTabProps {
  healthData: SystemHealthData | null;
}

/**
 * Thuật toán: Ánh Xạ Màu Sắc Ngữ Nghĩa & Định Dạng Thời Lượng Hoạt Động Thực Tế (`resolveStatusTheme` & `formatUptimeDuration`)
 * Mục đích: Trình bày trung thực trạng thái dịch vụ hạ tầng (`ONLINE`, `DEGRADED`, `OFFLINE`), mặc định rơi về `OFFLINE` / `—` khi mất kết nối thay vì hiển thị xanh giả tạo.
 */
function resolveStatusTheme(status: HealthStatusLabel) {
  if (status === 'ONLINE') {
    return { textClass: 'text-[#008A05]', Icon: CheckCircle2 };
  }
  if (status === 'DEGRADED') {
    return { textClass: 'text-[#E07912]', Icon: AlertTriangle };
  }
  return { textClass: 'text-[#C13515]', Icon: XCircle };
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

export function SystemHealthTab({ healthData }: SystemHealthTabProps) {
  // CONFLICT-RESOLVED: Loại bỏ giá trị mặc định giả lập ONLINE và độ trễ 1.2ms khi dữ liệu sức khỏe rỗng hoặc lỗi 503.
  const gatewayStatus: HealthStatusLabel = healthData?.status ?? 'OFFLINE';
  const dbStatus: HealthStatusLabel = healthData?.database?.status ?? 'OFFLINE';
  const cacheStatus: HealthStatusLabel = healthData?.cache?.status ?? 'OFFLINE';

  const gatewayTheme = resolveStatusTheme(gatewayStatus);
  const dbTheme = resolveStatusTheme(dbStatus);
  const cacheTheme = resolveStatusTheme(cacheStatus);

  const GatewayIcon = gatewayTheme.Icon;
  const DbIcon = dbTheme.Icon;
  const CacheIcon = cacheTheme.Icon;

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
        <CardHeader className="pb-2">
          <CardDescription className="text-xs text-[#717171]">
            Trạng thái API Gateway
          </CardDescription>
          <CardTitle
            className={`text-xl font-bold flex items-center gap-2 ${gatewayTheme.textClass}`}
          >
            <GatewayIcon size={20} strokeWidth={1.75} aria-hidden="true" />
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
            <DbIcon size={20} strokeWidth={1.75} aria-hidden="true" />
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
            <CacheIcon size={20} strokeWidth={1.75} aria-hidden="true" />
            <span>{cacheStatus}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-[#717171]">
          {cacheStatus === 'ONLINE'
            ? 'Đồng bộ PDP & Rate-limit: Sẵn sàng'
            : 'Kết nối bộ đệm gián đoạn'}
        </CardContent>
      </Card>

      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
        <CardHeader className="pb-2">
          <CardDescription className="text-xs text-[#717171]">
            Thời gian hoạt động (Uptime)
          </CardDescription>
          <CardTitle className="text-xl font-bold text-[#222222]">
            {formatUptimeDuration(healthData?.uptimeSeconds)}
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-[#717171]">
          {healthData && healthData.uptimeSeconds > 0
            ? `${healthData.uptimeSeconds} giây liên tục`
            : 'Chưa ghi nhận thông số tiến trình'}
        </CardContent>
      </Card>
    </div>
  );
}
