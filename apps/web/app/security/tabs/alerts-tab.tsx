'use client';

import { useState } from 'react';
import { Search } from 'lucide-react';
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
import { filterSecurityAlerts } from '../helpers';
import type { SecurityAlertItem } from '../types';

interface AlertsTabProps {
  alerts: SecurityAlertItem[];
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

/**
 * Thuật toán: Lọc Đa Chiều Hàng Đợi Cảnh Báo SOC Theo Mức Độ Nghiêm Trọng & Trạng Thái (`AlertsTab`)
 * Mục đích: Giúp cán bộ SOC khoanh vùng nhanh cảnh báo `CRITICAL`/`HIGH` hoặc cảnh báo đang mở (`OPEN`/`INVESTIGATING`) trên cả màn hình desktop và điện thoại `375px`.
 */
export function AlertsTab({ alerts, onSelectAlert }: AlertsTabProps) {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredAlerts = filterSecurityAlerts(alerts, severityFilter, statusFilter);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Hàng đợi cảnh báo bảo mật ({filteredAlerts.length})
          </CardTitle>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full lg:w-auto min-w-0">
            <div>
              <label htmlFor="soc-alert-severity-filter" className="sr-only">
                Lọc theo mức độ nghiêm trọng
              </label>
              <select
                id="soc-alert-severity-filter"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi mức độ nghiêm trọng</option>
                <option value="CRITICAL">CRITICAL (Nghiêm trọng)</option>
                <option value="HIGH">HIGH (Cao)</option>
                <option value="MEDIUM">MEDIUM (Trung bình)</option>
                <option value="LOW">LOW (Thấp)</option>
              </select>
            </div>

            <div>
              <label htmlFor="soc-alert-status-filter" className="sr-only">
                Lọc theo trạng thái xử lý
              </label>
              <select
                id="soc-alert-status-filter"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi trạng thái xử lý</option>
                <option value="OPEN">OPEN (Chờ xử lý)</option>
                <option value="INVESTIGATING">INVESTIGATING (Đang điều tra)</option>
                <option value="RESOLVED">RESOLVED (Đã xử lý)</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE (Báo động giả)</option>
              </select>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
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
            {filteredAlerts.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-xs text-[#717171]">
                  Không có cảnh báo bảo mật nào khớp với bộ lọc hiện tại
                </TableCell>
              </TableRow>
            ) : (
              filteredAlerts.map((alert) => (
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
      </CardContent>
    </Card>
  );
}
