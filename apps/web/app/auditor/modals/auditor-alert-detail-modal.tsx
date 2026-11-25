'use client';

import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { apiClient } from '@/lib/api-client';
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
  formatAlertSeverityLabel,
  formatAlertStatusLabel,
  formatAuditActionLabel,
  formatAuditOutcomeLabel,
  formatDetectionRuleLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import { mapAuditorAlertDto } from '../forensics-helpers';
import type { AuditorAlertApiDto, AuditorAlertItem } from '../types';

interface AuditorAlertDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: AuditorAlertItem | null;
}

/**
 * Thuật toán: Xem Bằng Chứng Chi Tiết Cảnh Báo An Ninh Chế Độ Chỉ Đọc Độc Lập (`AuditorAlertDetailModal`, UC36)
 * Mục đích: Nạp đầy đủ `GET /security-alerts/:id` (mô tả, ghi chú điều tra, kết luận xử lý, nhật ký kiểm toán liên kết) mà tuyệt đối không có thao tác sửa đổi trạng thái.
 */
export function AuditorAlertDetailModal({
  open,
  onOpenChange,
  alert,
}: AuditorAlertDetailModalProps) {
  const [fetchedAlert, setFetchedAlert] = useState<AuditorAlertItem | null>(null);

  useEffect(() => {
    if (!open || !alert?.id || alert.id === '—') return;
    let cancelled = false;
    apiClient<AuditorAlertApiDto>(`/security-alerts/${encodeURIComponent(alert.id)}`)
      .then((dto) => {
        if (!cancelled) setFetchedAlert(mapAuditorAlertDto(dto));
      })
      .catch(() => {
        // Giữ dữ liệu tóm tắt từ danh sách nếu tải chi tiết thất bại tạm thời
      });
    return () => {
      cancelled = true;
    };
  }, [alert?.id, open]);

  const active = fetchedAlert && alert && fetchedAlert.id === alert.id ? fetchedAlert : alert;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex flex-wrap items-center justify-between gap-2 pr-8">
            <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
              <ShieldAlert
                size={20}
                strokeWidth={1.75}
                className="text-[#C13515] shrink-0"
                aria-hidden="true"
              />
              <span>Chi tiết cảnh báo an ninh</span>
            </DialogTitle>
            <Badge variant="info">Chế độ chỉ đọc</Badge>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Bằng chứng kỹ thuật, ghi chú điều tra và nhật ký kiểm toán liên kết của cảnh báo.
          </DialogDescription>
        </DialogHeader>

        {active && (
          <div className="space-y-3 py-1 text-xs">
            <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={
                    active.severity === 'CRITICAL'
                      ? 'destructive'
                      : active.severity === 'HIGH'
                        ? 'warning'
                        : 'info'
                  }
                >
                  {formatAlertSeverityLabel(active.severity)}
                </Badge>
                <Badge
                  variant={
                    active.status === 'OPEN'
                      ? 'destructive'
                      : active.status === 'INVESTIGATING' || active.status === 'ESCALATED'
                        ? 'warning'
                        : 'success'
                  }
                >
                  {formatAlertStatusLabel(active.status)}
                </Badge>
              </div>
              <div className="font-semibold text-sm text-[#222222] break-words">{active.title}</div>
              <div className="text-[#717171]">{formatDetectionRuleLabel(active.ruleCode)}</div>
              {active.description && (
                <p className="text-[#222222] leading-relaxed break-words">{active.description}</p>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-[#ebebeb]">
                <div>
                  <span className="text-[#717171] block">Đối tượng phát hiện</span>
                  <span className="font-semibold text-[#222222]">{active.detectedUserName}</span>
                </div>
                <div>
                  <span className="text-[#717171] block">Địa chỉ IP nguồn</span>
                  <span className="font-mono text-[#222222]">{active.ipAddress}</span>
                </div>
                <div className="sm:col-span-2">
                  <span className="text-[#717171] block">Thời điểm phát hiện</span>
                  <span className="text-[#222222] tabular-nums">
                    {formatSafeDateVi(active.detectedAt, { includeTime: true })}
                  </span>
                </div>
              </div>
            </div>

            {active.resolutionNote && (
              <div className="rounded-[16px] border border-[#008A05]/20 bg-[#008A05]/5 p-3 space-y-1">
                <div className="font-semibold text-[#008A05]">Kết luận xử lý</div>
                <p className="text-[#222222] break-words">{active.resolutionNote}</p>
              </div>
            )}

            {active.notes && active.notes.length > 0 && (
              <div className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 space-y-2">
                <div className="font-semibold text-[#222222]">
                  Ghi chú điều tra ({active.notes.length})
                </div>
                <div className="space-y-2 max-h-36 overflow-y-auto">
                  {active.notes.map((n, idx) => (
                    <div
                      key={n.id ?? idx}
                      className="rounded-[12px] bg-[#f7f7f7] p-2.5 space-y-0.5"
                    >
                      <div className="flex justify-between gap-2 text-[11px] text-[#717171]">
                        <span className="font-semibold text-[#222222]">{n.authorName}</span>
                        <span className="tabular-nums">
                          {formatSafeDateVi(n.createdAt, { includeTime: true })}
                        </span>
                      </div>
                      <p className="text-[#222222] break-words">{n.note}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {active.linkedAuditLogs && active.linkedAuditLogs.length > 0 && (
              <div className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 space-y-2">
                <div className="font-semibold text-[#222222]">
                  Nhật ký kiểm toán liên kết ({active.linkedAuditLogs.length})
                </div>
                <ul className="space-y-1.5 max-h-36 overflow-y-auto">
                  {active.linkedAuditLogs.map((log, idx) => (
                    <li
                      key={log.id || idx}
                      className="rounded-[12px] bg-[#f7f7f7] px-2.5 py-1.5 flex flex-wrap justify-between gap-2"
                    >
                      <span className="font-medium text-[#008489]">
                        {formatAuditActionLabel(log.action)}
                      </span>
                      <span className="text-[#717171] tabular-nums">
                        {formatAuditOutcomeLabel(log.outcome)} ·{' '}
                        {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
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
