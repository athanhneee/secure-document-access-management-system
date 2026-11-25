'use client';

import { AlertTriangle, Network, Search, ShieldCheck } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  formatAlertSeverityLabel,
  formatDetectionRuleLabel,
  formatSafeDateVi,
  formatServiceHealthLabel,
} from '@/lib/ui-labels';
import type { NetworkDlpStatus, SecurityAlertItem } from '../types';
import { NetworkDlpBlueprint, NetworkDlpOverview } from './network-dlp-overview';

interface NetworkDlpTabProps {
  dlpAlerts: SecurityAlertItem[];
  totalDlpAlerts: number;
  dlpStatus: NetworkDlpStatus;
  tabError?: string | null | undefined;
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

/**
 * Thuật toán: Giám Sát Chống Thất Thoát Dữ Liệu Mạng (DLP) Theo Trạng Thái Worker Thực & Danh Sách Vi Phạm Độc Lập (`NetworkDlpTab`)
 * Mục đích: Không báo xanh giả qua `/health/ready`, không hardcode chế độ chặn và đọc danh sách cảnh báo DLP trực tiếp từ máy chủ (#06, #13).
 */
export function NetworkDlpTab({
  dlpAlerts,
  totalDlpAlerts,
  dlpStatus,
  tabError,
  onSelectAlert,
}: NetworkDlpTabProps) {
  const gatewayHealth = dlpStatus.gatewayHealth;
  const healthBadgeVariant =
    gatewayHealth === 'ONLINE'
      ? 'success'
      : gatewayHealth === 'DEGRADED'
        ? 'warning'
        : 'destructive';
  const healthLabel = formatServiceHealthLabel(gatewayHealth);

  const modeBadgeVariant =
    dlpStatus.enforcementMode === 'BLOCK'
      ? 'danger'
      : dlpStatus.enforcementMode === 'AUDIT_ONLY'
        ? 'warning'
        : 'neutral';
  const modeBadgeLabel =
    dlpStatus.enforcementMode === 'BLOCK'
      ? 'Chế độ chặn vi phạm (BLOCK)'
      : dlpStatus.enforcementMode === 'AUDIT_ONLY'
        ? 'Chế độ chỉ giám sát (AUDIT_ONLY)'
        : dlpStatus.enforcementMode === 'DISABLED'
          ? 'DLP đang tắt theo cấu hình'
          : 'Mất kết nối dịch vụ DLP';

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
            <Network size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Giám sát chống thất thoát dữ liệu mạng (DLP)</span>
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Badge variant={healthBadgeVariant}>{healthLabel}</Badge>
            <Badge variant={modeBadgeVariant}>{modeBadgeLabel}</Badge>
          </div>
        </div>

        {tabError && (
          <Alert variant="destructive" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2">{tabError}</AlertDescription>
          </Alert>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        <NetworkDlpOverview dlpStatus={dlpStatus} />

        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
              Cảnh báo chống thất thoát dữ liệu ({totalDlpAlerts})
            </h3>
            <span className="text-xs text-[#717171]">
              {dlpStatus.checkedAt
                ? `Kiểm tra lúc ${formatSafeDateVi(dlpStatus.checkedAt, { includeTime: true })}`
                : 'Ghi nhận từ hệ thống giám sát luồng dữ liệu'}
            </span>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] overflow-hidden">
            <Table>
              <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                <TableRow>
                  <TableHead className="text-xs text-[#717171]">Mức độ</TableHead>
                  <TableHead className="text-xs text-[#717171]">Hành vi phát hiện</TableHead>
                  <TableHead className="text-xs text-[#717171]">Đối tượng liên quan</TableHead>
                  <TableHead className="text-xs text-[#717171]">Địa chỉ IP nguồn</TableHead>
                  <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
                  <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dlpAlerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-7 text-[#717171] text-xs">
                      {gatewayHealth === 'ONLINE' ? (
                        <div className="flex items-center justify-center gap-2">
                          <ShieldCheck
                            size={20}
                            strokeWidth={1.75}
                            className="text-[#008A05] shrink-0"
                            aria-hidden="true"
                          />
                          <span className="font-medium text-[#222222]">
                            Cổng giám sát DLP đang hoạt động ({modeBadgeLabel}) · Chưa ghi nhận vi
                            phạm rò rỉ dữ liệu.
                          </span>
                        </div>
                      ) : (
                        <div className="flex items-center justify-center gap-2">
                          <AlertTriangle
                            size={20}
                            strokeWidth={1.75}
                            className="text-[#C13515] shrink-0"
                            aria-hidden="true"
                          />
                          <span className="font-medium text-[#222222]">
                            Dịch vụ giám sát DLP mạng hiện chưa sẵn sàng ({healthLabel} ·{' '}
                            {modeBadgeLabel}). Hãy kiểm tra tiến trình Worker DLP.
                          </span>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ) : (
                  dlpAlerts.map((alert) => (
                    <TableRow
                      key={alert.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell>
                        <Badge
                          variant={
                            alert.severity === 'CRITICAL'
                              ? 'destructive'
                              : alert.severity === 'HIGH'
                                ? 'warning'
                                : 'info'
                          }
                        >
                          {formatAlertSeverityLabel(alert.severity)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-semibold text-xs text-[#222222]">{alert.title}</div>
                        <div className="text-xs text-[#717171]">
                          {formatDetectionRuleLabel(alert.ruleCode)}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        {alert.detectedUserName || 'Chưa định danh'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {alert.ipAddress}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                        {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Chi tiết"
                          icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onSelectAlert(alert)}
                        />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </div>

        <NetworkDlpBlueprint />
      </CardContent>
    </Card>
  );
}
