'use client';

import { RefreshCw, Info, ChevronLeft, ChevronRight } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
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

export function AuditHistoryTab({
  auditLogs,
  auditPage,
  auditTotalPages,
  auditTotal,
  isLoadingAudit,
  onLoadPage,
  onInspectLog,
}: AuditHistoryTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Nhật ký truy vết bảo mật (Audit Log)
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Dữ liệu kiểm toán thực từ máy chủ cho các tài liệu thuộc quyền sở hữu của bạn
          </CardDescription>
        </div>
        <InteractiveHoverButton
          variant="secondary"
          size="sm"
          text="Làm mới log"
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
        />
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Thời điểm</TableHead>
                <TableHead className="text-xs text-[#717171]">Người thực hiện</TableHead>
                <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                <TableHead className="text-xs text-[#717171]">Tài liệu / Phiên</TableHead>
                <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Chi tiết</TableHead>
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
                    Đang tải dữ liệu kiểm toán...
                  </TableCell>
                </TableRow>
              ) : auditLogs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-[#717171] text-xs">
                    Chưa có sự kiện kiểm toán nào được ghi nhận cho tài liệu của bạn
                  </TableCell>
                </TableRow>
              ) : (
                auditLogs.map((log) => (
                  <TableRow
                    key={log.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell className="text-xs text-[#222222] whitespace-nowrap">
                      {new Date(log.occurredAt).toLocaleString('vi-VN')}
                    </TableCell>
                    <TableCell>
                      <div className="text-xs font-semibold text-[#222222]">
                        {log.actorUsername || 'system'}
                      </div>
                      {log.actorUserId && (
                        <div className="text-[13px] text-[#717171]">ID: {log.actorUserId}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-[13px]">
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {log.documentId && (
                        <div className="text-xs font-mono text-[#717171]">
                          Doc: {log.documentId.slice(0, 8)}...
                        </div>
                      )}
                      {log.accessSessionId && (
                        <div className="text-[13px] text-[#008489]">
                          Sess: {log.accessSessionId.slice(0, 12)}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-[#717171] font-mono">
                      {log.ipAddress || '—'}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={log.outcome === 'SUCCESS' ? 'success' : 'destructive'}
                        className="text-[13px]"
                      >
                        {log.outcome}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
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
        </div>

        <div className="p-3 border-t border-[#ebebeb] flex items-center justify-between text-xs text-[#717171]">
          <span>Tổng số: {auditTotal} bản ghi</span>
          <div className="flex items-center gap-2">
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={auditPage <= 1 || isLoadingAudit}
              onClick={() => onLoadPage(auditPage - 1)}
            />
            <span>
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
