'use client';

import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { formatAuditActionLabel, formatAuditOutcomeLabel, formatSafeDateVi } from '@/lib/ui-labels';
import type { AuditLogItem } from '../types';

interface AuditDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  auditLog: AuditLogItem | null;
}

export function AuditDetailModal({ open, onOpenChange, auditLog }: AuditDetailModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chi tiết lịch sử truy cập
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Thông tin ghi nhận sự kiện truy cập tài liệu trong nhật ký kiểm toán.
          </DialogDescription>
        </DialogHeader>

        {auditLog && (
          <div className="py-1 text-xs space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-2.5 bg-[#f7f7f7] p-3.5 rounded-[16px] border border-[#ebebeb]">
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Thời điểm
                </div>
                <div className="mt-0.5 font-semibold text-[#222222]">
                  {formatSafeDateVi(auditLog.occurredAt, { includeTime: true })}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Hành động
                </div>
                <div className="mt-0.5 font-semibold text-[#222222] break-words">
                  {formatAuditActionLabel(auditLog.action)}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Người thực hiện
                </div>
                <div className="mt-0.5 font-semibold text-[#222222] break-all">
                  {auditLog.actorUsername || 'Hệ thống'}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Kết quả
                </div>
                <div className="mt-0.5">
                  <Badge variant={auditLog.outcome === 'SUCCESS' ? 'success' : 'destructive'}>
                    {formatAuditOutcomeLabel(auditLog.outcome)}
                  </Badge>
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Địa chỉ IP
                </div>
                <div className="mt-0.5 font-mono text-[#222222] break-all">
                  {auditLog.ipAddress || '—'}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Phiên truy cập
                </div>
                <div className="mt-0.5 font-semibold text-[#222222]">
                  {auditLog.accessSessionId ? 'Đã ghi nhận phiên bảo mật' : '—'}
                </div>
              </div>
            </div>

            {auditLog.entryHash && (
              <details className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] px-3 py-2">
                <summary className="cursor-pointer font-medium text-[#717171] hover:text-[#222222]">
                  Thông tin đối soát toàn vẹn
                </summary>
                <div className="mt-2 font-mono text-xs break-all text-[#717171]">
                  {auditLog.entryHash}
                </div>
              </details>
            )}
          </div>
        )}

        <DialogFooter>
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Đóng"
            onClick={() => onOpenChange(false)}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
