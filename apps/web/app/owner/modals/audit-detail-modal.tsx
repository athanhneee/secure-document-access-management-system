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
            Chi tiết bản ghi kiểm toán #{auditLog?.id}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Chữ ký chuỗi Merkle/Hash chain đảm bảo tính toàn vẹn không thể làm giả
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
                  {new Date(auditLog.occurredAt).toLocaleString('vi-VN')}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Hành động
                </div>
                <div className="mt-0.5 font-semibold text-[#222222] break-all">
                  {auditLog.action}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Người thực hiện
                </div>
                <div className="mt-0.5 font-semibold text-[#222222] break-all">
                  {auditLog.actorUsername || 'system'}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[#717171]">
                  Kết quả
                </div>
                <div className="mt-0.5">
                  <Badge variant={auditLog.outcome === 'SUCCESS' ? 'success' : 'destructive'}>
                    {auditLog.outcome}
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
                  Mã phiên
                </div>
                <div className="mt-0.5 font-mono text-[#222222] break-all">
                  {auditLog.accessSessionId || '—'}
                </div>
              </div>
            </div>

            <div className="space-y-1">
              <span className="font-medium text-[#222222]">Mã băm chuỗi (Entry Hash)</span>
              <div className="p-2.5 rounded-[12px] bg-[#f7f7f7] border border-[#ebebeb] font-mono text-xs break-all text-[#717171]">
                {auditLog.entryHash}
              </div>
            </div>

            {auditLog.details && Object.keys(auditLog.details).length > 0 && (
              <div className="space-y-1">
                <span className="font-medium text-[#222222]">Chi tiết sự kiện</span>
                <pre className="sda-table-scroll p-2.5 rounded-[12px] bg-[#f7f7f7] border border-[#ebebeb] font-mono text-xs text-[#222222] overflow-x-auto overflow-y-auto max-h-44">
                  {JSON.stringify(auditLog.details, null, 2)}
                </pre>
              </div>
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
