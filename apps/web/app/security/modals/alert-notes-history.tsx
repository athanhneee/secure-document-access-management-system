'use client';

import { FileText, MessageSquare } from 'lucide-react';
import type { AlertNoteItem } from '../types';

interface AlertNotesHistoryProps {
  ruleCode: string;
  detectedUserName?: string | undefined;
  ipAddress?: string | undefined;
  resolutionNote?: string | null | undefined;
  notes?: AlertNoteItem[] | undefined;
}

/**
 * Thuật toán: Tóm tắt Định danh Cảnh báo, Kết luận Xử lý & Nhật ký Điều tra SOC (`AlertNotesHistory`)
 * Mục đích: Trình bày thông tin quy tắc vi phạm, kết luận đóng cảnh báo (`resolutionNote`) và chuỗi ghi chú rà soát nội bộ (`notes`) ngay trong hộp thoại điều tra.
 */
export function AlertNotesHistory({
  ruleCode,
  detectedUserName,
  ipAddress,
  resolutionNote,
  notes,
}: AlertNotesHistoryProps) {
  const hasResolution = Boolean(resolutionNote && resolutionNote.trim());
  const noteItems = notes ?? [];

  return (
    <div className="space-y-3">
      <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Quy tắc:</span>
          <span className="font-bold text-[#222222] text-right">{ruleCode}</span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Đối tượng:</span>
          <span className="font-medium text-[#222222] text-right">{detectedUserName || '—'}</span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-[#717171]">Địa chỉ IP:</span>
          <span className="font-bold text-[#222222] text-right">{ipAddress || '—'}</span>
        </div>
      </div>

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
                      ? new Date(entry.createdAt).toLocaleString('vi-VN')
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
