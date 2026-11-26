'use client';

import { useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
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
import { formatByteSizeVi } from '../helpers';
import type { ExportJobItem } from '../types';

interface ExportQueueTabProps {
  exportJobs: ExportJobItem[];
  canExport?: boolean;
  downloadingJobId?: string | null;
  onOpenExportModal: () => void;
  onDownloadExport: (job: ExportJobItem) => Promise<void>;
}

function getExportStatusVariant(status: string) {
  if (status === 'COMPLETED') return 'success';
  if (status === 'FAILED') return 'destructive';
  if (status === 'EXPIRED') return 'neutral';
  return 'warning';
}

/**
 * Thuật toán: Lịch Sử Xuất Báo Cáo Tuân Thủ Đóng An Toàn (`canExport = false`) Kèm Siêu Dữ Liệu Toàn Vẹn & Giao Diện Mobile 375px (`ExportQueueTab`)
 * Mục đích: Hiển thị đầy đủ số dòng, dung lượng, hạn tải 24h, mã băm SHA-256 (có nút sao chép), thông điệp lỗi khi FAILED và khóa nút chống nhấn đúp khi đang tải.
 */
export function ExportQueueTab({
  exportJobs,
  canExport = false,
  downloadingJobId = null,
  onOpenExportModal,
  onDownloadExport,
}: ExportQueueTabProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function handleCopyText(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
    } catch {
      // Bỏ qua lỗi trình duyệt không cho phép clipboard
    }
  }

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
        {/* Mobile 375px card view */}
        <div className="md:hidden divide-y divide-[#ebebeb]">
          {exportJobs.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-[#717171]">
              Chưa có yêu cầu xuất báo cáo kiểm toán nào.
            </div>
          ) : (
            exportJobs.map((job) => {
              const canDownload = job.status === 'COMPLETED' && !job.isExpired;
              const displayStatus = job.isExpired ? 'EXPIRED' : job.status;
              const isJobDownloading = downloadingJobId === job.id;
              return (
                <article key={job.id} className="p-3.5 space-y-2 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="font-semibold text-[#222222]">
                        {formatExportTypeLabel(job.exportType)}
                      </div>
                      <div className="font-mono text-[#717171] truncate">{job.id}</div>
                    </div>
                    <Badge variant={getExportStatusVariant(displayStatus)}>
                      {formatExportStatusLabel(displayStatus)}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[#717171]">
                    <Badge variant="secondary">{formatExportFormatLabel(job.format)}</Badge>
                    <span>
                      {job.rowCount !== null && job.rowCount !== undefined
                        ? `${job.rowCount} dòng`
                        : '—'}{' '}
                      · {formatByteSizeVi(job.fileSizeBytes)}
                    </span>
                  </div>
                  <div className="text-[#717171] tabular-nums">
                    Tạo: {formatSafeDateVi(job.createdAt, { includeTime: true })}
                    {job.expiresAt
                      ? ` · Hết hạn: ${formatSafeDateVi(job.expiresAt, { includeTime: true })}`
                      : ''}
                  </div>
                  {job.sha256Hash && job.sha256Hash !== '—' && (
                    <div className="flex items-center justify-between gap-2 rounded-[12px] bg-[#f7f7f7] px-2.5 py-1.5">
                      <span className="font-mono text-[11px] text-[#717171] truncate">
                        SHA-256: {job.sha256Hash.slice(0, 20)}…
                      </span>
                      <button
                        type="button"
                        onClick={() => void handleCopyText(job.sha256Hash!, `sha-${job.id}`)}
                        aria-label={`Sao chép mã băm SHA-256 của yêu cầu ${job.id.slice(0, 8)}`}
                        className="inline-flex min-h-11 min-w-11 sm:min-h-9 sm:min-w-9 items-center justify-center gap-1 rounded-full px-2 text-xs font-medium text-[#222222] hover:bg-[#ebebeb] cursor-pointer shrink-0"
                      >
                        {copiedKey === `sha-${job.id}` ? (
                          <Check
                            size={16}
                            strokeWidth={2}
                            className="text-[#008A05]"
                            aria-hidden="true"
                          />
                        ) : (
                          <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  )}
                  {displayStatus === 'FAILED' && job.errorMessage && (
                    <p className="text-xs text-[#C13515] break-words">Lỗi: {job.errorMessage}</p>
                  )}
                  {canDownload && canExport && (
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Tải tệp"
                      icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                      isLoading={isJobDownloading}
                      disabled={isJobDownloading}
                      onClick={() => onDownloadExport(job)}
                      className="w-full"
                    />
                  )}
                </article>
              );
            })
          )}
        </div>

        {/* Desktop table view */}
        <div className="hidden md:block">
          <Table>
            <caption className="sr-only">
              Danh sách lịch sử yêu cầu xuất báo cáo tuân thủ và trạng thái tải tệp
            </caption>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mã yêu cầu</TableHead>
                <TableHead className="text-xs text-[#717171]">Loại báo cáo</TableHead>
                <TableHead className="text-xs text-[#717171]">Định dạng</TableHead>
                <TableHead className="text-xs text-[#717171]">Dữ liệu / SHA-256</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {exportJobs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-xs text-[#717171]">
                    Chưa có yêu cầu xuất báo cáo kiểm toán nào.
                  </TableCell>
                </TableRow>
              ) : (
                exportJobs.map((job) => {
                  const canDownload = job.status === 'COMPLETED' && !job.isExpired;
                  const displayStatus = job.isExpired ? 'EXPIRED' : job.status;
                  const isJobDownloading = downloadingJobId === job.id;
                  return (
                    <TableRow
                      key={job.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell title={job.id} className="font-mono text-xs text-[#222222]">
                        {job.id.slice(0, 8)}…
                      </TableCell>
                      <TableCell className="text-xs font-medium text-[#222222]">
                        {formatExportTypeLabel(job.exportType)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{formatExportFormatLabel(job.format)}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-[#717171]">
                        <div className="tabular-nums text-[#222222]">
                          {job.rowCount !== null && job.rowCount !== undefined
                            ? `${job.rowCount} dòng`
                            : '—'}{' '}
                          · {formatByteSizeVi(job.fileSizeBytes)}
                        </div>
                        {job.sha256Hash && job.sha256Hash !== '—' && (
                          <div className="flex items-center gap-1 mt-0.5">
                            <span
                              title={job.sha256Hash}
                              className="font-mono text-[11px] text-[#717171]"
                            >
                              {job.sha256Hash.slice(0, 14)}…
                            </span>
                            <button
                              type="button"
                              onClick={() => void handleCopyText(job.sha256Hash!, `sha-${job.id}`)}
                              aria-label={`Sao chép mã băm SHA-256 của báo cáo ${job.id.slice(0, 8)}`}
                              className="inline-flex min-h-11 min-w-11 sm:min-h-9 sm:min-w-9 items-center justify-center rounded-full px-2 text-[#717171] hover:text-[#222222] hover:bg-[#ebebeb] cursor-pointer"
                            >
                              {copiedKey === `sha-${job.id}` ? (
                                <Check
                                  size={16}
                                  strokeWidth={2}
                                  className="text-[#008A05]"
                                  aria-hidden="true"
                                />
                              ) : (
                                <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                              )}
                            </button>
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap tabular-nums">
                        <div>Tạo: {formatSafeDateVi(job.createdAt, { includeTime: true })}</div>
                        {job.expiresAt && (
                          <div className="text-[11px]">
                            Hết hạn: {formatSafeDateVi(job.expiresAt, { includeTime: true })}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getExportStatusVariant(displayStatus)}>
                          {formatExportStatusLabel(displayStatus)}
                        </Badge>
                        {displayStatus === 'FAILED' && job.errorMessage && (
                          <div
                            title={job.errorMessage}
                            className="text-[11px] text-[#C13515] max-w-[180px] truncate mt-0.5"
                          >
                            {job.errorMessage}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        {canDownload && canExport && (
                          <InteractiveHoverButton
                            size="sm"
                            variant="secondary"
                            text="Tải tệp"
                            icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                            isLoading={isJobDownloading}
                            disabled={isJobDownloading}
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
        </div>
      </CardContent>
    </Card>
  );
}
