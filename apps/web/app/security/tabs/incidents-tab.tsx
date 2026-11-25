'use client';

import { FileCheck, FileSearch } from 'lucide-react';
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
import { formatIncidentStatusLabel } from '@/lib/ui-labels';
import type { IncidentItem } from '../types';

interface IncidentsTabProps {
  incidents: IncidentItem[];
  canCreateIncident?: boolean;
  onOpenCreateIncident: () => void;
  onSelectIncident: (incident: IncidentItem) => void;
}

/**
 * Thuật toán: Theo Dõi Vòng Đời Hồ Sơ Sự Cố & Tiến Độ Khắc Phục (`IncidentsTab`)
 * Mục đích: Tổng hợp tiến độ hoàn thành Corrective Actions và kích hoạt hộp thoại xử lý chi tiết cho từng hồ sơ sự cố SOC.
 */
export function IncidentsTab({
  incidents,
  canCreateIncident = true,
  onOpenCreateIncident,
  onSelectIncident,
}: IncidentsTabProps) {
  return (
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Hồ sơ sự cố an ninh ({incidents.length})
        </CardTitle>
        {canCreateIncident && (
          <InteractiveHoverButton
            size="sm"
            variant="primary"
            text="Tạo hồ sơ mới"
            icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onOpenCreateIncident}
            className="shrink-0"
          />
        )}
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Tiêu đề sự cố</TableHead>
              <TableHead className="text-xs text-[#717171]">Tóm tắt diễn biến</TableHead>
              <TableHead className="text-xs text-[#717171]">Hành động khắc phục</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {incidents.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                  Chưa có hồ sơ sự cố an ninh nào được tạo.
                </TableCell>
              </TableRow>
            ) : (
              incidents.map((inc) => (
                <TableRow key={inc.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    <div>{inc.title}</div>
                    {inc.incidentCode && (
                      <div className="text-[13px] font-mono text-[#717171]">{inc.incidentCode}</div>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-[#222222] max-w-sm truncate">
                    {inc.summary}
                  </TableCell>
                  <TableCell className="text-xs text-[#222222]">
                    {inc.actions && inc.actions.length > 0 ? (
                      <span className="text-[#008A05] font-medium">
                        {
                          inc.actions.filter(
                            (a) => Boolean(a.completedAt) || Boolean(a.isCompleted),
                          ).length
                        }
                        /{inc.actions.length} hoàn tất
                      </span>
                    ) : (
                      <span className="text-[#717171]">Chưa có hành động</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        inc.status === 'CLOSED'
                          ? 'success'
                          : inc.status === 'DRAFT'
                            ? 'warning'
                            : 'info'
                      }
                    >
                      {formatIncidentStatusLabel(inc.status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Chi tiết"
                      icon={<FileSearch size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onSelectIncident(inc)}
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
