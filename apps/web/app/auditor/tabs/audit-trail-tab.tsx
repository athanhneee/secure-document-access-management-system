'use client';

import { Calendar, Search } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { AuditLogItem } from '../types';

interface AuditTrailTabProps {
  logs: AuditLogItem[];
  outcomeFilter: string;
  actionFilter: string;
  fromDate: string;
  toDate: string;
  onOutcomeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
  onFromDateChange: (value: string) => void;
  onToDateChange: (value: string) => void;
}

export function AuditTrailTab({
  logs,
  outcomeFilter,
  actionFilter,
  fromDate,
  toDate,
  onOutcomeFilterChange,
  onActionFilterChange,
  onFromDateChange,
  onToDateChange,
}: AuditTrailTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="pb-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <CardTitle className="text-base text-[#222222]">
              Dấu vết hoạt động (Audit Trail Explorer)
            </CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              Append-only · Chống chỉnh sửa · Bảo vệ thông tin nhạy cảm không bị lộ trong log
            </CardDescription>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Lọc theo kết quả kiểm toán"
              value={outcomeFilter}
              onChange={(e) => onOutcomeFilterChange(e.target.value)}
              className="h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              <option value="ALL">Mọi kết quả</option>
              <option value="SUCCESS">SUCCESS (Thành công)</option>
              <option value="DENIED">DENIED (Từ chối)</option>
              <option value="FAILED">FAILED (Thất bại)</option>
            </select>

            <div className="relative w-48">
              <Search
                size={16}
                strokeWidth={1.75}
                className="pointer-events-none absolute left-3.5 top-3 text-[#717171]"
                aria-hidden="true"
              />
              <Input
                type="text"
                aria-label="Lọc theo mã hành động"
                placeholder="Lọc theo hành động..."
                value={actionFilter}
                onChange={(e) => onActionFilterChange(e.target.value)}
                className="pl-10 h-10 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
              />
            </div>

            <div className="flex items-center gap-1.5 text-xs text-[#717171]">
              <Calendar
                size={16}
                strokeWidth={1.75}
                className="text-[#717171]"
                aria-hidden="true"
              />
              <Input
                type="date"
                value={fromDate}
                onChange={(e) => onFromDateChange(e.target.value)}
                aria-label="Từ ngày"
                className="h-10 w-36 text-xs rounded-full bg-[#f7f7f7] border-[#ebebeb] px-3 text-[#222222] focus:border-[#FF385C]"
              />
              <span className="text-[#b0b0b0]">-</span>
              <Input
                type="date"
                value={toDate}
                onChange={(e) => onToDateChange(e.target.value)}
                aria-label="Đến ngày"
                className="h-10 w-36 text-xs rounded-full bg-[#f7f7f7] border-[#ebebeb] px-3 text-[#222222] focus:border-[#FF385C]"
              />
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Thời gian (UTC)</TableHead>
                <TableHead className="text-xs text-[#717171]">Người thực hiện</TableHead>
                <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
                <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                <TableHead className="text-xs text-[#717171]">Correlation ID / Hash</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map((log) => (
                <TableRow key={log.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-bold text-xs text-[#717171]">
                    {log.occurredAt
                      ? new Date(log.occurredAt).toISOString().replace('T', ' ').slice(0, 19)
                      : '—'}
                  </TableCell>
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    {log.actorUsername}
                  </TableCell>
                  {/* CONFLICT-RESOLVED: Chuẩn hóa màu hành động sang màu info chính thức #008489 theo rules/ui-design-system.md §5 */}
                  <TableCell className="font-bold text-xs text-[#008489]">{log.action}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        log.outcome === 'SUCCESS'
                          ? 'success'
                          : log.outcome === 'DENIED'
                            ? 'warning'
                            : 'destructive'
                      }
                    >
                      {log.outcome}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#717171]">
                    {log.ipAddress || '—'}
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#717171] max-w-xs truncate">
                    {log.correlationId}
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
