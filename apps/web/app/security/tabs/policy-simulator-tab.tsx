'use client';

import { ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ServerSimulatorPanel } from '@/components/abac/server-simulator-panel';
import type { SimulationEnvironment } from '@/components/abac/simulator-evaluator';

const DEFAULT_SIM_ENV: SimulationEnvironment = {
  currentTime: '10:00',
  ip: '127.0.0.1',
  trustedNetwork: true,
  deviceTrust: true,
  mfa: true,
  riskScore: 10,
};

/**
 * Thuật toán: Không Gian Mô Phỏng Chính Sách ABAC (UC09) Dành Cho Cán Bộ An Ninh Thông Tin (`PolicySimulatorTab`)
 * Mục đích: Cung cấp công cụ thực thi quyền `POLICY:SIMULATE` ngay trong phân hệ `/security` mà vẫn giữ nguyên Phân tách nhiệm vụ (SoD) ngăn truy cập `/admin` (#05).
 */
export function PolicySimulatorTab() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
          <ShieldCheck size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
          <span>Mô phỏng đánh giá chính sách ABAC (UC09)</span>
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Kiểm thử quyết định cho phép/từ chối và các nghĩa vụ bảo mật (watermark, MFA, giới hạn
          phiên) trực tiếp trên động cơ PDP máy chủ mà không làm thay đổi chính sách đang hiệu lực.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ServerSimulatorPanel defaultEnvironment={DEFAULT_SIM_ENV} />
      </CardContent>
    </Card>
  );
}
