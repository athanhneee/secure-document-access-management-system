'use client';

import { useEffect, useRef } from 'react';
import { RefreshCw, Info, ChevronLeft, ChevronRight } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { formatAuditActionLabel, formatAuditOutcomeLabel, formatSafeDateVi } from '@/lib/ui-labels';
import type { AuditLogItem } from '../types';

interface AuditHistoryTabProps {
  auditLogs: AuditLogItem[];
  auditPage: number;
  auditTotalPages: number;
  auditTotal: number;
  isLoadingAudit: boolean;
  onLoadPage: (page: number) => void;
  onInspectLog: (log: AuditLogItem) => void;
}

/**
 * Thuật toán: Bảng Nhật Ký Truy Vết Tài Liệu Cuộn Có Trần Chiều Cao & Chống Xô Lệch Cột (`AuditHistoryTab`)
 * Mục đích: Đặt danh sách sự kiện truy cập tài liệu của Chủ sở hữu trong khung cuộn cố định tiêu đề cột, cắt gọn các chuỗi mã dài kèm `title` và tự động cuộn về đầu bảng khi chuyển trang.
 */
export function AuditHistoryTab({
  auditLogs,
  auditPage,
  auditTotalPages,
  auditTotal,
  isLoadingAudit,
  onLoadPage,
  onInspectLog,
}: AuditHistoryTabProps) {
  const tableScrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [auditPage]);

  return (
    <Card>
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Lịch sử truy cập tài liệu ({auditTotal})
        </CardTitle>
        <InteractiveHoverButton
          variant="secondary"
          size="sm"
          text="Làm mới"
          icon={
            <RefreshCw
              size={16}
              strokeWidth={1.75}
              className={isLoadingAudit ? 'animate-spin' : ''}
              aria-hidden="true"
            />
          }
          onClick={() => onLoadPage(auditPage)}
          disabled={isLoadingAudit}
          className="shrink-0"
        />
      </CardHeader>
      <CardContent className="p-0">
        <Table containerRef={tableScrollRef} className="min-w-[840px] table-fixed">
          <TableHeader>
            <TableRow>
              <TableHead className="w-[172px] text-xs text-[#717171]">Thời điểm</TableHead>
              <TableHead className="w-[140px] text-xs text-[#717171]">Người thực hiện</TableHead>
              <TableHead className="w-[185px] text-xs text-[#717171]">Hành động</TableHead>
              <TableHead className="text-xs text-[#717171]">Thông tin liên quan</TableHead>
              <TableHead className="w-[115px] text-xs text-[#717171]">Địa chỉ IP</TableHead>
              <TableHead className="w-[110px] text-xs text-[#717171]">Kết quả</TableHead>
              <TableHead className="w-[92px] text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoadingAudit ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-[#717171] text-xs">
                  <RefreshCw
                    size={20}
                    strokeWidth={1.75}
                    className="animate-spin mx-auto mb-2 text-[#FF385C]"
                    aria-hidden="true"
                  />
                  Đang tải lịch sử truy cập…
                </TableCell>
              </TableRow>
            ) : auditLogs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-[#717171] text-xs">
                  Chưa có sự kiện truy cập nào được ghi nhận cho tài liệu của bạn.
                </TableCell>
              </TableRow>
            ) : (
              auditLogs.map((log) => (
                <TableRow key={log.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="text-xs text-[#222222] whitespace-nowrap tabular-nums truncate">
                    {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                  </TableCell>
                  <TableCell>
                    <div
                      title={log.actorUsername || 'Hệ thống'}
                      className="text-xs font-semibold text-[#222222] truncate"
                    >
                      {log.actorUsername || 'Hệ thống'}
                    </div>
                  </TableCell>
                  <TableCell title={formatAuditActionLabel(log.action)} className="truncate">
                    <Badge variant="secondary" className="text-xs max-w-full truncate">
                      {formatAuditActionLabel(log.action)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-[#222222] truncate">
                    {log.documentId ? (
                      <div className="text-xs text-[#717171] truncate">
                        Tài liệu #{log.documentId.slice(0, 8)}
                      </div>
                    ) : (
                      <span className="text-[#717171]">—</span>
                    )}
                    {log.accessSessionId && (
                      <div className="text-xs text-[#008489] truncate">Có phiên đọc bảo mật</div>
                    )}
                  </TableCell>
                  <TableCell
                    title={log.ipAddress || '—'}
                    className="text-xs text-[#717171] font-mono whitespace-nowrap tabular-nums truncate"
                  >
                    {log.ipAddress || '—'}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <Badge
                      variant={log.outcome === 'SUCCESS' ? 'success' : 'destructive'}
                      className="text-xs"
                    >
                      {formatAuditOutcomeLabel(log.outcome)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <InteractiveHoverButton
                      variant="ghost"
                      size="sm"
                      text="Xem"
                      icon={<Info size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onInspectLog(log)}
                    />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>

        <div className="px-4 py-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
          <span>
            Tổng số: <strong className="text-[#222222]">{auditTotal}</strong> bản ghi
          </span>
          <div className="flex items-center gap-2">
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={auditPage <= 1 || isLoadingAudit}
              onClick={() => onLoadPage(auditPage - 1)}
            />
            <span className="font-semibold text-[#222222] whitespace-nowrap tabular-nums">
              Trang {auditPage} / {Math.max(1, auditTotalPages)}
            </span>
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={auditPage >= auditTotalPages || isLoadingAudit}
              onClick={() => onLoadPage(auditPage + 1)}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
