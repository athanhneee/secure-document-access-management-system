'use client';

import { useState } from 'react';
import { Check, Copy, ShieldCheck } from 'lucide-react';
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
  formatAbacReasonLabel,
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
 * Thuật toán: Hiển Thị Đầy Đủ Hồ Sơ Pháp Chứng Bản Ghi Kiểm Toán Chế Độ Chỉ Đọc Kèm Nút Sao Chép Nhanh (`AuditorLogDetailModal`)
 * Mục đích: Trình bày đầy đủ thông tin nghiệp vụ & kỹ thuật (`userAgent`, `actorUserId`, `documentId`, `accessSessionId`, `hmacKeyVersion`, mã hành động gốc, mã băm liền trước/hiện tại phân biệt chính xác Genesis `#1` vs lỗi thiếu liên kết).
 */
function isCopyableAuditValue(value: string | null | undefined): value is string {
  if (!value) return false;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed !== '—';
}

export function AuditorLogDetailModal({
  open,
  onOpenChange,
  auditLog,
}: AuditorLogDetailModalProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function handleCopy(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
    } catch {
      // Bỏ qua lỗi trình duyệt không cho phép clipboard
    }
  }

  const isGenesisEntry = String(auditLog?.chainSequence ?? '') === '1';

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
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-2.5 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5">
              <div className="min-w-0">
                <div className="text-[#717171]">Thời điểm</div>
                <div className="font-semibold text-[#222222] tabular-nums">
                  {formatSafeDateVi(auditLog.occurredAt, { includeTime: true })}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Người thực hiện</div>
                <div className="font-semibold text-[#222222]">
                  {auditLog.actorUsername === 'SYSTEM' ? 'Hệ thống' : auditLog.actorUsername}
                  {auditLog.actorUserId ? ` (#${auditLog.actorUserId})` : ''}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Hành động</div>
                <div className="font-semibold text-[#008489] break-words">
                  {formatAuditActionLabel(auditLog.action)}
                </div>
                <div className="font-mono text-[11px] text-[#717171] break-all">
                  {auditLog.action}
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
                <div className="font-mono text-[#222222] tabular-nums">
                  {auditLog.ipAddress || '—'}
                </div>
              </div>
              <div className="min-w-0 sm:col-span-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#717171]">Mã truy vết</span>
                  {isCopyableAuditValue(auditLog.correlationId) && (
                    <button
                      type="button"
                      onClick={() => void handleCopy(auditLog.correlationId, 'corr')}
                      aria-label="Sao chép mã truy vết"
                      className="inline-flex min-h-11 sm:min-h-9 items-center gap-1 rounded-full px-3 py-1 text-xs font-medium text-[#222222] hover:bg-[#ebebeb] cursor-pointer"
                    >
                      {copiedKey === 'corr' ? (
                        <Check
                          size={16}
                          strokeWidth={2}
                          className="text-[#008A05]"
                          aria-hidden="true"
                        />
                      ) : (
                        <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                      )}
                      <span>{copiedKey === 'corr' ? 'Đã chép' : 'Sao chép'}</span>
                    </button>
                  )}
                </div>
                <div className="font-mono text-[#222222] break-all">{auditLog.correlationId}</div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Phân vùng chuỗi</div>
                <div className="font-medium text-[#222222]">
                  {formatAuditPartitionLabel(auditLog.chainPartition)}
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[#717171]">Số thứ tự &amp; Phiên bản khóa</div>
                <div className="font-mono text-[#222222] tabular-nums">
                  #{auditLog.chainSequence !== undefined ? String(auditLog.chainSequence) : '—'}
                  {auditLog.hmacKeyVersion !== undefined ? ` · v${auditLog.hmacKeyVersion}` : ''}
                </div>
              </div>
              {auditLog.reasonCode && (
                <div className="min-w-0 sm:col-span-2">
                  <div className="text-[#717171]">Lý do / Mã quy tắc</div>
                  <div className="font-medium text-[#222222] break-words">
                    {formatAbacReasonLabel(auditLog.reasonCode)}
                  </div>
                  <div className="font-mono text-[11px] text-[#717171] break-all">
                    {auditLog.reasonCode}
                  </div>
                </div>
              )}
              {auditLog.userAgent && (
                <div className="min-w-0 sm:col-span-2">
                  <div className="text-[#717171]">Thiết bị / Trình duyệt (User-Agent)</div>
                  <div className="font-mono text-[11px] text-[#222222] break-words">
                    {auditLog.userAgent}
                  </div>
                </div>
              )}
            </div>

            <details className="rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3.5 space-y-2.5">
              <summary className="cursor-pointer font-semibold text-[#222222] select-none">
                Thông tin kỹ thuật đối soát mật mã
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

                {auditLog.documentId && (
                  <div className="space-y-1">
                    <div className="font-medium text-[#717171]">Mã tài liệu liên quan</div>
                    <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2 font-mono text-xs break-all text-[#222222]">
                      {auditLog.documentId}
                    </div>
                  </div>
                )}

                {auditLog.accessSessionId && (
                  <div className="space-y-1">
                    <div className="font-medium text-[#717171]">Mã phiên đọc tài liệu</div>
                    <div className="rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2 font-mono text-xs break-all text-[#222222]">
                      {auditLog.accessSessionId}
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[#717171]">Mã băm bản ghi liền trước</span>
                    {isCopyableAuditValue(auditLog.previousHash) && (
                      <button
                        type="button"
                        onClick={() => void handleCopy(auditLog.previousHash!, 'prevHash')}
                        aria-label="Sao chép mã băm bản ghi liền trước"
                        className="inline-flex min-h-11 sm:min-h-9 items-center gap-1 rounded-full px-3 py-1 text-xs font-medium text-[#222222] hover:bg-[#f7f7f7] cursor-pointer"
                      >
                        {copiedKey === 'prevHash' ? (
                          <Check
                            size={16}
                            strokeWidth={2}
                            className="text-[#008A05]"
                            aria-hidden="true"
                          />
                        ) : (
                          <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                        )}
                        <span>{copiedKey === 'prevHash' ? 'Đã chép' : 'Sao chép'}</span>
                      </button>
                    )}
                  </div>
                  <div
                    className={`rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7] p-2.5 font-mono text-xs break-all ${
                      !auditLog.previousHash && !isGenesisEntry
                        ? 'text-[#C13515]'
                        : 'text-[#717171]'
                    }`}
                  >
                    {auditLog.previousHash
                      ? auditLog.previousHash
                      : isGenesisEntry
                        ? 'Bản ghi khởi đầu chuỗi (Genesis #1)'
                        : 'Thiếu mã băm bản ghi liền trước (bất thường chuỗi)'}
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[#717171]">
                      Mã băm bản ghi hiện tại ({auditLog.chainAlgorithm || 'HMAC-SHA-256'})
                    </span>
                    {isCopyableAuditValue(auditLog.entryHash) && (
                      <button
                        type="button"
                        onClick={() => void handleCopy(auditLog.entryHash!, 'entryHash')}
                        aria-label="Sao chép mã băm bản ghi hiện tại"
                        className="inline-flex min-h-11 sm:min-h-9 items-center gap-1 rounded-full px-3 py-1 text-xs font-medium text-[#222222] hover:bg-[#f7f7f7] cursor-pointer"
                      >
                        {copiedKey === 'entryHash' ? (
                          <Check
                            size={16}
                            strokeWidth={2}
                            className="text-[#008A05]"
                            aria-hidden="true"
                          />
                        ) : (
                          <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                        )}
                        <span>{copiedKey === 'entryHash' ? 'Đã chép' : 'Sao chép'}</span>
                      </button>
                    )}
                  </div>
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
