'use client';

import { AlertTriangle, Network, Search, ShieldCheck } from 'lucide-react';
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
import type { GatewayHealthStatus, SecurityAlertItem } from '../types';
import { NetworkDlpBlueprint, NetworkDlpOverview } from './network-dlp-overview';

interface NetworkDlpTabProps {
  dlpAlerts: SecurityAlertItem[];
  gatewayHealth?: GatewayHealthStatus | undefined;
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

export function NetworkDlpTab({
  dlpAlerts,
  gatewayHealth = 'ONLINE',
  onSelectAlert,
}: NetworkDlpTabProps) {
  const healthBadgeVariant =
    gatewayHealth === 'ONLINE'
      ? 'success'
      : gatewayHealth === 'DEGRADED'
        ? 'warning'
        : 'destructive';
  const healthLabel =
    gatewayHealth === 'ONLINE'
      ? 'ONLINE · TCP 1344'
      : gatewayHealth === 'DEGRADED'
        ? 'DEGRADED · TCP 1344'
        : 'OFFLINE · TCP 1344';

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
            <Network size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Network DLP Gateway (ICAP · TCP 1344)</span>
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Badge variant={healthBadgeVariant}>{healthLabel}</Badge>
            <Badge variant="danger">BLOCK VIOLATIONS</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <NetworkDlpOverview />

        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
              Cảnh báo rò rỉ dữ liệu tầng mạng ({dlpAlerts.length})
            </h3>
            <span className="text-xs text-[#717171]">Đồng bộ từ ICAP Gateway</span>
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
                            ICAP Gateway đang hoạt động · Chưa ghi nhận vi phạm Egress
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
                            Kết nối dịch vụ DLP đang suy giảm ({gatewayHealth})
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
                          {alert.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-semibold text-xs text-[#222222]">{alert.title}</div>
                        <div className="text-xs font-mono text-[#717171]">{alert.ruleCode}</div>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        {alert.detectedUserName || 'Chưa định danh'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {alert.ipAddress}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171]">
                        {new Date(alert.detectedAt).toLocaleString('vi-VN')}
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
