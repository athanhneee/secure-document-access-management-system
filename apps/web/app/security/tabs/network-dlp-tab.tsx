'use client';

import { Network, Search, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { SecurityAlertItem } from '../types';
import { NetworkDlpBlueprint, NetworkDlpOverview } from './network-dlp-overview';

interface NetworkDlpTabProps {
  dlpAlerts: SecurityAlertItem[];
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

export function NetworkDlpTab({ dlpAlerts, onSelectAlert }: NetworkDlpTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <CardTitle className="text-base text-[#222222] flex items-center gap-2">
              <Network size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
              <span>Cổng phòng chống thất thoát dữ liệu tầng mạng (Network DLP Gateway)</span>
            </CardTitle>
            <CardDescription className="text-xs text-[#717171] mt-1">
              Tích hợp máy chủ ICAP Server (RFC 3507) kiểm tra luồng dữ liệu ra ngoài Internet
              (Egress Traffic) kết nối thiết bị biên (Squid, Symantec, Forcepoint, F5)
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="success">ONLINE · TCP 1344</Badge>
            <Badge variant="danger">BLOCK VIOLATIONS</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <NetworkDlpOverview />

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
              Cảnh báo rò rỉ dữ liệu tầng mạng gần đây ({dlpAlerts.length})
            </h3>
            <span className="text-[11px] text-[#717171]">
              Tự động đồng bộ từ sự kiện ICAP Gateway
            </span>
          </div>

          <div className="overflow-x-auto rounded-[16px] border border-[#ebebeb]">
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
                    <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                      <div className="flex flex-col items-center justify-center gap-1.5">
                        <ShieldCheck
                          size={24}
                          strokeWidth={1.75}
                          className="text-[#008A05]"
                          aria-hidden="true"
                        />
                        <span className="font-medium text-[#222222]">
                          Cổng Network DLP ICAP Server đang bảo vệ an toàn luồng dữ liệu Egress
                        </span>
                        <span className="text-[11px] text-[#717171]">
                          Chưa ghi nhận sự cố rò rỉ dữ liệu mật hoặc khóa bí mật ra ngoài thiết bị
                          biên.
                        </span>
                      </div>
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
                        <div className="text-[11px] font-mono text-[#717171]">{alert.ruleCode}</div>
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
                      <TableCell className="text-right">
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
