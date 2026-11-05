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
          <div className="py-2 text-xs space-y-2">
            <div className="grid grid-cols-2 gap-2 bg-[#f7f7f7] p-3 rounded-[20px] border border-[#ebebeb]">
              <div>
                Thời điểm: <strong>{new Date(auditLog.occurredAt).toLocaleString('vi-VN')}</strong>
              </div>
              <div>
                Hành động: <strong>{auditLog.action}</strong>
              </div>
              <div>
                Người dùng: <strong>{auditLog.actorUsername || 'system'}</strong>
              </div>
              <div>
                Kết quả:{' '}
                <Badge
                  variant={auditLog.outcome === 'SUCCESS' ? 'success' : 'destructive'}
                  className="text-[13px]"
                >
                  {auditLog.outcome}
                </Badge>
              </div>
              <div>
                IP: <span className="font-mono">{auditLog.ipAddress || '—'}</span>
              </div>
              <div>
                Phiên: <span className="font-mono">{auditLog.accessSessionId || '—'}</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="font-medium text-[#222222]">Hash chuỗi kiểm toán (Entry Hash):</span>
              <div className="p-2 rounded bg-[#f7f7f7] border font-mono text-[13px] break-all text-[#717171]">
                {auditLog.entryHash}
              </div>
            </div>

            {auditLog.details && Object.keys(auditLog.details).length > 0 && (
              <div className="space-y-1">
                <span className="font-medium text-[#222222]">Thuộc tính chi tiết (Details):</span>
                <pre className="p-2 rounded bg-[#f7f7f7] border font-mono text-[13px] text-[#222222] overflow-x-auto max-h-36">
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
