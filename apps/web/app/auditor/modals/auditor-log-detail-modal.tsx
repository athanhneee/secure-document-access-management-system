'use client';

import { ShieldCheck } from 'lucide-react';
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
import {
  formatAuditActionLabel,
  formatAuditObjectTypeLabel,
  formatAuditOutcomeLabel,
  formatAuditPartitionLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import type { AuditLogItem } from '../types';

interface AuditorLogDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  auditLog: AuditLogItem | null;
}

/**
 * Thuật toán: Hiển Thị Thông Tin Bản Ghi Kiểm Toán Chế Độ Chỉ Đọc (`AuditorLogDetailModal`)
 * Mục đích: Trình bày thông tin nghiệp vụ dễ đọc cho kiểm toán viên và gom các mã băm/JSON kỹ thuật vào phần mở rộng đối soát.
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
          <div className="flex flex-wrap items-center justify-between gap-2 pr-8">
            <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
              <ShieldCheck
                size={20}
                strokeWidth={1.75}
                className="text-[#008489] shrink-0"
                aria-hidden="true"
              />
              <span>Chi tiết bản ghi kiểm toán</span>
            </DialogTitle>
            <Badge variant="info">Chế độ chỉ đọc</Badge>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Thông tin chi tiết sự kiện được ghi nhận trong chuỗi nhật ký kiểm toán toàn vẹn.
          </DialogDescription>
        </DialogHeader>

        {auditLog && (
          <div className="space-y-3 py-1 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-2.5 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5">
              <div className="min-w-0">
                <div className="text-[#717171]">Thời điểm</div>
                <div className="font-semibold text-[#222222]">
                  {formatSafeDateVi(auditLog.occurredAt, { includeTime: true })}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Người thực hiện</div>
                <div className="font-semibold text-[#222222]">
                  {auditLog.actorUsername === 'SYSTEM' ? 'Hệ thống' : auditLog.actorUsername}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Hành động</div>
                <div className="font-semibold text-[#008489] break-words">
                  {formatAuditActionLabel(auditLog.action)}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171] mb-0.5">Kết quả</div>
                <Badge
                  variant={
                    auditLog.outcome === 'SUCCESS'
                      ? 'success'
                      : auditLog.outcome === 'DENIED'
                        ? 'warning'
                        : 'destructive'
                  }
                >
                  {formatAuditOutcomeLabel(auditLog.outcome)}
                </Badge>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Đối tượng</div>
                <div className="font-medium text-[#222222] break-words">
                  {formatAuditObjectTypeLabel(auditLog.objectType)}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Địa chỉ IP</div>
                <div className="font-mono text-[#222222]">{auditLog.ipAddress || '—'}</div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Mã truy vết</div>
                <div className="font-mono text-[#222222] break-all">{auditLog.correlationId}</div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Phân vùng chuỗi</div>
                <div className="font-medium text-[#222222]">
                  {formatAuditPartitionLabel(auditLog.chainPartition)}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Số thứ tự chuỗi</div>
                <div className="font-mono text-[#222222]">
                  {auditLog.chainSequence !== undefined ? String(auditLog.chainSequence) : '—'}
                </div>
              </div>
              {auditLog.reasonCode && (
                <div className="min-w-0">
                  <div className="text-[#717171]">Mã lý do</div>
                  <div className="font-mono text-[#222222] break-all">{auditLog.reasonCode}</div>
                </div>
              )}
            </div>

            <details className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 space-y-2.5">
              <summary className="cursor-pointer font-semibold text-[#222222] select-none">
                Thông tin kỹ thuật đối soát
              </summary>
              <div className="space-y-2.5 pt-2">
                {auditLog.objectId && (
                  <div className="space-y-1">
                    <div className="font-medium text-[#717171]">Mã định danh đối tượng</div>
                    <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2 font-mono text-xs break-all text-[#222222]">
                      {auditLog.objectId}
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <div className="font-medium text-[#717171]">Mã băm bản ghi liền trước</div>
                  <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-xs break-all text-[#717171]">
                    {auditLog.previousHash || 'Bản ghi khởi đầu chuỗi'}
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="font-medium text-[#717171]">Mã băm bản ghi hiện tại</div>
                  <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-xs break-all text-[#008A05]">
                    {auditLog.entryHash || '—'}
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="font-medium text-[#717171]">Dữ liệu chi tiết kèm theo</div>
                  <pre className="sda-table-scroll rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-xs text-[#222222] overflow-x-auto overflow-y-auto max-h-44">
                    {JSON.stringify(auditLog.details ?? {}, null, 2)}
                  </pre>
                </div>
              </div>
            </details>
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
