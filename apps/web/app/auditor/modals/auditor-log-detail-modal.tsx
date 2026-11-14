'use client';

import { Lock, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { AuditLogItem } from '../types';

interface AuditorLogDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  auditLog: AuditLogItem | null;
}

/**
 * Thuật toán: Hiển Thị Siêu Dữ Liệu Pháp Chứng Bản Ghi Kiểm Toán Chế Độ Chỉ Đọc (`AuditorLogDetailModal`)
 * Mục đích: Trình bày đầy đủ dấu vết mật mã HMAC-SHA256 (`correlationId`, `chainPartition`, `chainSequence`, `previousHash`, `entryHash`, `ipAddress`, `reasonCode`, `details`) tuân thủ nghiêm ngặt nguyên tắc Phân tách Trách nhiệm (SoD Read-Only).
 */
export function AuditorLogDetailModal({
  open,
  onOpenChange,
  auditLog,
}: AuditorLogDetailModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
              <ShieldCheck
                size={20}
                strokeWidth={1.75}
                className="text-[#008489] shrink-0"
                aria-hidden="true"
              />
              <span>Bản ghi pháp chứng kiểm toán #{auditLog?.id}</span>
            </DialogTitle>
            <Badge variant="info">Read-Only · SoD</Badge>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Siêu dữ liệu sổ cái bất biến liên kết chuỗi băm HMAC-SHA256 chống chối bỏ và chỉnh sửa
          </DialogDescription>
        </DialogHeader>

        {auditLog && (
          <div className="space-y-3 py-2 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5">
              <div>
                <span className="text-[#717171]">Thời điểm (UTC): </span>
                <strong className="text-[#222222]">
                  {auditLog.occurredAt ? new Date(auditLog.occurredAt).toISOString() : '—'}
                </strong>
              </div>
              <div>
                <span className="text-[#717171]">Người thực hiện: </span>
                <strong className="text-[#222222]">{auditLog.actorUsername}</strong>
                {auditLog.actorUserId && (
                  <span className="text-[#717171]"> (#{auditLog.actorUserId})</span>
                )}
              </div>
              <div>
                <span className="text-[#717171]">Hành động: </span>
                <strong className="font-mono text-[#008489]">{auditLog.action}</strong>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[#717171]">Kết quả:</span>
                <Badge
                  variant={
                    auditLog.outcome === 'SUCCESS'
                      ? 'success'
                      : auditLog.outcome === 'DENIED'
                        ? 'warning'
                        : 'destructive'
                  }
                >
                  {auditLog.outcome}
                </Badge>
              </div>
              <div>
                <span className="text-[#717171]">Đối tượng: </span>
                <span className="font-mono text-[#222222]">
                  {auditLog.objectType}
                  {auditLog.objectId ? ` #${auditLog.objectId}` : ''}
                </span>
              </div>
              <div>
                <span className="text-[#717171]">Địa chỉ IP: </span>
                <span className="font-mono font-semibold text-[#222222]">
                  {auditLog.ipAddress || '—'}
                </span>
              </div>
              <div>
                <span className="text-[#717171]">Mã lý do (reasonCode): </span>
                <span className="font-mono font-semibold text-[#222222]">
                  {auditLog.reasonCode || '—'}
                </span>
              </div>
              <div>
                <span className="text-[#717171]">Correlation ID: </span>
                <span className="font-mono text-[#222222] break-all">{auditLog.correlationId}</span>
              </div>
              <div>
                <span className="text-[#717171]">Phân vùng (chainPartition): </span>
                <strong className="font-mono text-[#222222]">
                  {auditLog.chainPartition || 'GLOBAL'}
                </strong>
              </div>
              <div>
                <span className="text-[#717171]">Số thứ tự (chainSequence): </span>
                <strong className="font-mono text-[#222222]">
                  {auditLog.chainSequence !== undefined ? String(auditLog.chainSequence) : '—'}
                </strong>
              </div>
            </div>

            <div className="space-y-1">
              <div className="font-medium text-[#222222]">
                Mã băm khối liền trước (previousHash):
              </div>
              <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-[13px] break-all text-[#717171]">
                {auditLog.previousHash || 'GENESIS (Khối khởi nguyên phân vùng)'}
              </div>
            </div>

            <div className="space-y-1">
              <div className="font-medium text-[#222222]">
                Mã băm toàn vẹn bản ghi hiện tại (entryHash):
              </div>
              <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-[13px] break-all text-[#008A05]">
                {auditLog.entryHash || '—'}
              </div>
            </div>

            <div className="space-y-1">
              <div className="font-medium text-[#222222]">
                Siêu dữ liệu chi tiết sự kiện (JSON details):
              </div>
              <pre className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-[13px] text-[#222222] overflow-x-auto max-h-44">
                {JSON.stringify(auditLog.details ?? {}, null, 2)}
              </pre>
            </div>

            <div className="flex items-center gap-2 rounded-[14px] border border-[#ebebeb] bg-[#f7f7f7] px-3 py-2 text-[#717171]">
              <Lock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
              <span>Bản ghi kiểm toán ở chế độ chỉ đọc tuyệt đối — không cho phép chỉnh sửa.</span>
            </div>
          </div>
        )}

        <DialogFooter>
          <InteractiveHoverButton
            type="button"
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
