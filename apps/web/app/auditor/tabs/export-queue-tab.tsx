'use client';

import { Download } from 'lucide-react';
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
  formatExportFormatLabel,
  formatExportStatusLabel,
  formatExportTypeLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import type { ExportJobItem } from '../types';

interface ExportQueueTabProps {
  exportJobs: ExportJobItem[];
  canExport?: boolean;
  onOpenExportModal: () => void;
  onDownloadExport: (job: ExportJobItem) => void;
}

export function ExportQueueTab({
  exportJobs,
  canExport = true,
  onOpenExportModal,
  onDownloadExport,
}: ExportQueueTabProps) {
  return (
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Lịch sử xuất báo cáo ({exportJobs.length})
        </CardTitle>
        {canExport && (
          <InteractiveHoverButton
            size="sm"
            variant="primary"
            text="Tạo báo cáo mới"
            icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onOpenExportModal}
            className="shrink-0"
          />
        )}
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Mã yêu cầu</TableHead>
              <TableHead className="text-xs text-[#717171]">Loại báo cáo</TableHead>
              <TableHead className="text-xs text-[#717171]">Định dạng</TableHead>
              <TableHead className="text-xs text-[#717171]">Thời gian tạo</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {exportJobs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8 text-xs text-[#717171]">
                  Chưa có yêu cầu xuất báo cáo kiểm toán nào.
                </TableCell>
              </TableRow>
            ) : (
              exportJobs.map((job) => {
                const canDownload = job.status === 'COMPLETED' && !job.isExpired;
                const displayStatus = job.isExpired ? 'EXPIRED' : job.status;
                return (
                  <TableRow
                    key={job.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell className="font-mono text-xs text-[#222222]">{job.id}</TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {formatExportTypeLabel(job.exportType)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{formatExportFormatLabel(job.format)}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                      {formatSafeDateVi(job.createdAt, { includeTime: true })}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          displayStatus === 'COMPLETED'
                            ? 'success'
                            : displayStatus === 'FAILED'
                              ? 'destructive'
                              : displayStatus === 'EXPIRED'
                                ? 'neutral'
                                : 'warning'
                        }
                      >
                        {formatExportStatusLabel(displayStatus)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      {canDownload && canExport && (
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Tải tệp"
                          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onDownloadExport(job)}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
