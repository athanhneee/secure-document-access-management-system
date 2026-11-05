'use client';

import { Search } from 'lucide-react';
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

interface AlertsTabProps {
  alerts: SecurityAlertItem[];
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

export function AlertsTab({ alerts, onSelectAlert }: AlertsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Hàng đợi cảnh báo bảo mật (Security Alerts)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Phát hiện bất thường thời gian thực: tải ồ ạt, bị từ chối liên tục, ngoài giờ, IP lạ
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mức độ nghiêm trọng</TableHead>
                <TableHead className="text-xs text-[#717171]">Loại cảnh báo / Tiêu đề</TableHead>
                <TableHead className="text-xs text-[#717171]">Đối tượng phát hiện</TableHead>
                <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Xử lý</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.map((alert) => (
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
                    <div className="text-xs font-bold text-[#717171]">{alert.ruleCode}</div>
                  </TableCell>
                  <TableCell className="text-xs text-[#222222]">
                    {alert.detectedUserName || 'Chưa định danh'}
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#717171]">
                    {alert.ipAddress}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        alert.status === 'OPEN'
                          ? 'destructive'
                          : alert.status === 'INVESTIGATING'
                            ? 'warning'
                            : 'success'
                      }
                    >
                      {alert.status}
                    </Badge>
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
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
