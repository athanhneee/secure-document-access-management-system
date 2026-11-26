'use client';

import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
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
  formatAuditActionLabel,
  formatAuditObjectTypeLabel,
  formatAuditOutcomeLabel,
  formatAuditPartitionLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';

export interface AuditAnchorRow {
  id: string;
  chainPartition: string;
  anchorSequence: string;
  entryHash: string;
  signature: string;
  signerKeyId?: string | undefined;
  status?: string | undefined;
  anchoredAt: string;
}

export interface AuditLogRow {
  id: string;
  chainPartition?: string;
  action: string;
  actorUsername?: string | null;
  objectType?: string | null;
  outcome: string;
  ipAddress?: string | null;
  occurredAt: string;
}

/**
 * Thuật toán: Hiển Thị Thích Ứng `375px` Mobile Card & Desktop Table Cho Điểm Neo HMAC Và Nhật Ký Kiểm Toán SOC (`AuditAnchorsSection`, `AuditSystemLogsSection`)
 * Mục đích: Xóa bỏ hoàn toàn tràn ngang bảng 6 cột trên màn hình di động `375px` bằng danh sách thẻ dọc `md:hidden` song hành cùng bảng `hidden md:block`.
 */
export function AuditAnchorsSection({ anchors }: { anchors: AuditAnchorRow[] }) {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] overflow-hidden">
      <div className="md:hidden divide-y divide-[#ebebeb]">
        {anchors.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-[#717171]">
            Chưa có điểm neo chữ ký nào. Chọn phân vùng và bấm &quot;Tạo điểm neo HMAC&quot; để đóng
            dấu toàn vẹn.
          </div>
        ) : (
          anchors.map((a) => (
            <article key={a.id} className="p-3.5 space-y-1.5 bg-[#ffffff] text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-[#222222]">
                  {formatAuditPartitionLabel(a.chainPartition)} · #{a.anchorSequence}
                </span>
                <Badge variant={a.status === 'INVALID' ? 'destructive' : 'success'}>
                  {a.status === 'INVALID' ? 'Sai lệch' : 'Hợp lệ'}
                </Badge>
              </div>
              <div className="font-mono text-[#717171] truncate">{a.entryHash}</div>
              <div className="flex flex-wrap items-center justify-between gap-2 text-[#717171] tabular-nums">
                <span>Khóa ký: {a.signerKeyId || 'v1'}</span>
                <span>{formatSafeDateVi(a.anchoredAt, { includeTime: true })}</span>
              </div>
            </article>
          ))
        )}
      </div>

      <div className="hidden md:block">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Phân vùng</TableHead>
              <TableHead className="text-xs text-[#717171]">Số thứ tự neo</TableHead>
              <TableHead className="text-xs text-[#717171]">Mã băm bản ghi</TableHead>
              <TableHead className="text-xs text-[#717171]">Khóa ký</TableHead>
              <TableHead className="text-xs text-[#717171]">Thời điểm neo</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {anchors.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-6 text-xs text-[#717171]">
                  Chưa có điểm neo chữ ký nào. Chọn phân vùng và bấm &quot;Tạo điểm neo HMAC&quot;
                  để đóng dấu toàn vẹn.
                </TableCell>
              </TableRow>
            ) : (
              anchors.map((a) => (
                <TableRow key={a.id} className="border-b border-[#ebebeb]">
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    {formatAuditPartitionLabel(a.chainPartition)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#222222]">
                    #{a.anchorSequence}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#717171]">
                    {a.entryHash.slice(0, 16)}…
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#717171]">
                    {a.signerKeyId || 'v1'}
                  </TableCell>
                  <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                    {formatSafeDateVi(a.anchoredAt, { includeTime: true })}
                  </TableCell>
                  <TableCell>
                    <Badge variant={a.status === 'INVALID' ? 'destructive' : 'success'}>
                      {a.status === 'INVALID' ? 'Sai lệch' : 'Hợp lệ'}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export function AuditSystemLogsSection({
  logs,
  isLoading,
  logsPage,
  logsTotalPages,
  onPageChange,
}: {
  logs: AuditLogRow[];
  isLoading: boolean;
  logsPage: number;
  logsTotalPages: number;
  onPageChange: (page: number) => void;
}) {
  function getOutcomeVariant(outcome: string) {
    if (outcome === 'SUCCESS') return 'success' as const;
    if (outcome === 'DENIED') return 'destructive' as const;
    return 'warning' as const;
  }

  return (
    <>
      <div className="md:hidden divide-y divide-[#ebebeb]">
        {logs.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-[#717171]">
            {isLoading ? 'Đang tải nhật ký kiểm toán…' : 'Chưa có bản ghi nhật ký kiểm toán.'}
          </div>
        ) : (
          logs.map((log) => (
            <article key={log.id} className="p-3.5 space-y-2 bg-[#ffffff] text-xs">
              <div className="flex items-start justify-between gap-2">
                <span className="font-semibold text-[#222222] break-words">
                  {formatAuditActionLabel(log.action)}
                </span>
                <Badge variant={getOutcomeVariant(log.outcome)}>
                  {formatAuditOutcomeLabel(log.outcome)}
                </Badge>
              </div>
              <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#717171]">Tác nhân</span>
                  <span className="font-medium text-[#222222] truncate">
                    {log.actorUsername || 'Hệ thống'}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#717171]">Đối tượng</span>
                  <span className="text-[#222222] truncate">
                    {formatAuditObjectTypeLabel(log.objectType)}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#717171]">Địa chỉ IP</span>
                  <span className="font-mono text-[#222222] tabular-nums">
                    {log.ipAddress || '—'}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#717171]">Thời gian</span>
                  <span className="text-[#717171] tabular-nums">
                    {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                  </span>
                </div>
              </div>
            </article>
          ))
        )}
      </div>

      <div className="hidden md:block">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
              <TableHead className="text-xs text-[#717171]">Tác nhân</TableHead>
              <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
              <TableHead className="text-xs text-[#717171]">Đối tượng</TableHead>
              <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
              <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-6 text-xs text-[#717171]">
                  {isLoading ? 'Đang tải nhật ký kiểm toán…' : 'Chưa có bản ghi nhật ký kiểm toán.'}
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id} className="border-b border-[#ebebeb]">
                  <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                    {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                  </TableCell>
                  <TableCell className="text-xs font-medium text-[#222222]">
                    {log.actorUsername || 'Hệ thống'}
                  </TableCell>
                  <TableCell className="text-xs text-[#222222]">
                    {formatAuditActionLabel(log.action)}
                  </TableCell>
                  <TableCell className="text-xs text-[#717171]">
                    {formatAuditObjectTypeLabel(log.objectType)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#717171]">
                    {log.ipAddress || '—'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getOutcomeVariant(log.outcome)}>
                      {formatAuditOutcomeLabel(log.outcome)}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {logsTotalPages > 1 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
          <span className="tabular-nums">
            Trang {logsPage} / {logsTotalPages}
          </span>
          <div className="flex items-center gap-2">
            <InteractiveHoverButton
              type="button"
              size="sm"
              variant="secondary"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={logsPage <= 1}
              onClick={() => onPageChange(Math.max(1, logsPage - 1))}
            />
            <InteractiveHoverButton
              type="button"
              size="sm"
              variant="secondary"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={logsPage >= logsTotalPages}
              onClick={() => onPageChange(Math.min(logsTotalPages, logsPage + 1))}
            />
          </div>
        </div>
      )}
    </>
  );
}
