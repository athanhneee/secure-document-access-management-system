'use client';

import { Download } from 'lucide-react';
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
import type { ExportJobItem } from '../types';

interface ExportQueueTabProps {
  exportJobs: ExportJobItem[];
  onOpenExportModal: () => void;
  onDownloadExport: (job: ExportJobItem) => void;
}

export function ExportQueueTab({
  exportJobs,
  onOpenExportModal,
  onDownloadExport,
}: ExportQueueTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Hàng đợi xuất báo cáo kiểm toán bất đồng bộ
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Tệp xuất được lưu tạm 24 giờ và tự động thu hồi
          </CardDescription>
        </div>
        <InteractiveHoverButton
          size="sm"
          variant="primary"
          text="Tạo báo cáo mới"
          icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onOpenExportModal}
        />
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mã tác vụ</TableHead>
                <TableHead className="text-xs text-[#717171]">Loại báo cáo</TableHead>
                <TableHead className="text-xs text-[#717171]">Định dạng</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời gian tạo</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Tải về</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {exportJobs.map((job) => (
                <TableRow key={job.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-bold text-xs text-[#222222]">{job.id}</TableCell>
                  <TableCell className="text-xs text-[#222222]">{job.exportType}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{job.format}</Badge>
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#717171]">
                    {new Date(job.createdAt).toLocaleDateString('vi-VN')}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        job.status === 'COMPLETED'
                          ? 'success'
                          : job.status === 'FAILED'
                            ? 'destructive'
                            : 'warning'
                      }
                    >
                      {job.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Tải tệp"
                      icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onDownloadExport(job)}
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
