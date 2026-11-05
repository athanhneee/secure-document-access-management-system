'use client';

import { FileCheck } from 'lucide-react';
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
import type { IncidentItem } from '../types';

interface IncidentsTabProps {
  incidents: IncidentItem[];
  onOpenCreateIncident: () => void;
}

export function IncidentsTab({ incidents, onOpenCreateIncident }: IncidentsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Báo cáo sự cố an ninh thông tin
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Hồ sơ sự cố, bằng chứng liên kết và hành động khắc phục (Corrective Actions)
          </CardDescription>
        </div>
        <InteractiveHoverButton
          size="sm"
          variant="primary"
          text="Tạo báo cáo mới"
          icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onOpenCreateIncident}
        />
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tiêu đề sự cố</TableHead>
                <TableHead className="text-xs text-[#717171]">Tóm tắt tác động</TableHead>
                <TableHead className="text-xs text-[#717171]">Hành động khắc phục</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {incidents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-[#717171] text-xs">
                    Chưa có hồ sơ sự cố an ninh nào được tạo
                  </TableCell>
                </TableRow>
              ) : (
                incidents.map((inc) => (
                  <TableRow
                    key={inc.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell className="font-semibold text-xs text-[#222222]">
                      {inc.title}
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] max-w-sm truncate">
                      {inc.summary}
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {inc.actions && inc.actions.length > 0 ? (
                        <span className="text-[#008A05] font-medium">
                          {inc.actions.filter((a) => a.isCompleted).length}/{inc.actions.length}{' '}
                          hoàn tất
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
                        {inc.status}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
