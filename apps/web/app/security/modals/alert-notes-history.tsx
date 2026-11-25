'use client';

import { FileText, Info, Link2, MessageSquare } from 'lucide-react';
import {
  formatAuditActionLabel,
  formatAuditOutcomeLabel,
  formatDetectionRuleLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import type { AlertNoteItem, LinkedAuditLogSummary } from '../types';

interface AlertNotesHistoryProps {
  ruleCode: string;
  title?: string | undefined;
  description?: string | undefined;
  detectedUserName?: string | undefined;
  ipAddress?: string | undefined;
  detectedAt?: string | undefined;
  resolutionNote?: string | null | undefined;
  notes?: AlertNoteItem[] | undefined;
  linkedAuditLogs?: LinkedAuditLogSummary[] | undefined;
}

/**
 * Thuật toán: Hiển Thị Đầy Đủ Chi Tiết Kỹ Thuật (`description`), Bằng Chứng Audit Liên Kết, Kết Luận Xử Lý & Nhật Ký Điều Tra (`AlertNotesHistory`)
 * Mục đích: Khắc phục tình trạng nuốt mất `description` (chi tiết DLP/Audit) và `notes[]` của cảnh báo an ninh (#01, #02, #03).
 */
export function AlertNotesHistory({
  ruleCode,
  title,
  description,
  detectedUserName,
  ipAddress,
  detectedAt,
  resolutionNote,
  notes,
  linkedAuditLogs,
}: AlertNotesHistoryProps) {
  const hasDescription = Boolean(description && description.trim());
  const hasResolution = Boolean(resolutionNote && resolutionNote.trim());
  const noteItems = notes ?? [];
  const auditItems = linkedAuditLogs ?? [];

  return (
    <div className="space-y-3">
      <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
        {title && (
          <div className="font-semibold text-xs text-[#222222] pb-1 border-b border-[#ebebeb]">
            {title}
          </div>
        )}
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Quy tắc:</span>
          <span className="font-bold text-[#222222] text-right">
            {formatDetectionRuleLabel(ruleCode)}
          </span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Đối tượng:</span>
          <span className="font-medium text-[#222222] text-right">{detectedUserName || '—'}</span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Địa chỉ IP:</span>
          <span className="font-mono font-semibold text-[#222222] text-right">
            {ipAddress || '—'}
          </span>
        </div>
        {detectedAt && (
          <div className="flex justify-between gap-2">
            <span className="text-[#717171]">Thời điểm phát hiện:</span>
            <span className="font-medium text-[#222222] text-right">
              {formatSafeDateVi(detectedAt, { includeTime: true })}
            </span>
          </div>
        )}
      </div>

      {hasDescription && (
        <div className="rounded-[16px] border border-[#008489]/25 bg-[#008489]/5 p-3 space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-[#008489]">
            <Info size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>Chi tiết kỹ thuật phát hiện:</span>
          </div>
          <p className="text-xs text-[#222222] leading-relaxed whitespace-pre-wrap break-words">
            {description}
          </p>
        </div>
      )}

      {auditItems.length > 0 && (
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 space-y-1.5">
          <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
            <Link2 size={16} strokeWidth={1.75} className="text-[#717171]" aria-hidden="true" />
            <span>Nhật ký kiểm toán liên kết ({auditItems.length})</span>
          </div>
          <ul className="max-h-28 overflow-y-auto space-y-1 pr-1">
            {auditItems.slice(0, 10).map((log) => (
              <li
                key={log.id}
                className="flex flex-wrap items-center justify-between gap-1 rounded-[10px] bg-[#f7f7f7] px-2.5 py-1.5 text-xs"
              >
                <span className="font-medium text-[#222222]">
                  {formatAuditActionLabel(log.action)} · {formatAuditOutcomeLabel(log.outcome)}
                </span>
                <span className="font-mono text-[#717171]">
                  {log.ipAddress || '—'} · {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {hasResolution && (
        <div className="rounded-[16px] border border-[#008A05]/25 bg-[#008A05]/5 p-3 space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-[#008A05]">
            <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>Kết luận xử lý đã ghi nhận:</span>
          </div>
          <p className="text-xs text-[#222222] leading-relaxed whitespace-pre-wrap">
            {resolutionNote}
          </p>
        </div>
      )}

      {noteItems.length > 0 && (
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-2">
          <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
            <MessageSquare
              size={16}
              strokeWidth={1.75}
              className="text-[#008489]"
              aria-hidden="true"
            />
            <span>Nhật ký ghi chú điều tra ({noteItems.length})</span>
          </div>
          <ul className="max-h-36 overflow-y-auto space-y-2 pr-1">
            {noteItems.map((entry, idx) => (
              <li
                key={entry.id ?? `${entry.createdAt}-${idx}`}
                className="rounded-[12px] border border-[#ebebeb] bg-[#ffffff] p-2.5 space-y-1"
              >
                <div className="flex flex-wrap items-center justify-between gap-1 text-xs text-[#717171]">
                  <span className="font-semibold text-[#222222]">{entry.authorName}</span>
                  <span>
                    {entry.createdAt
                      ? formatSafeDateVi(entry.createdAt, { includeTime: true })
                      : 'Vừa xong'}
                  </span>
                </div>
                <p className="text-xs text-[#222222] leading-relaxed whitespace-pre-wrap">
                  {entry.note}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
