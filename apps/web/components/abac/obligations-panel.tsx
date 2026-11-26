'use client';

import { useState } from 'react';
import { FileCheck2 } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import type { VisualObligation } from './abac-models';
import {
  DEFAULT_SESSION_MINUTES,
  MAX_SESSION_MINUTES,
  MIN_SESSION_MINUTES,
  clampSessionMinutes,
  normalizeSessionMinutesDraftOnBlur,
  parseSessionMinutesDraft,
} from './policy-ast-helpers';

interface ObligationsPanelProps {
  obligations: VisualObligation[];
  onToggleObligation: (type: string) => void;
  onSetSessionMinutes: (minutes: number) => void;
  onSessionMinutesDraftChange?: ((draft: string | null) => void) | undefined;
}

const BOOLEAN_OBLIGATION_CARDS = [
  {
    id: 'ob-require-watermark',
    type: 'REQUIRE_WATERMARK',
    title: 'Gắn watermark bảo mật',
    description: 'Nhúng thông tin người dùng, thời gian và mã truy vết lên trang tài liệu.',
  },
  {
    id: 'ob-require-mfa',
    type: 'REQUIRE_MFA',
    title: 'Yêu cầu xác thực đa yếu tố (MFA)',
    description: 'Bắt buộc xác thực đa yếu tố trước khi mở tài liệu.',
  },
  {
    id: 'ob-forbid-download',
    type: 'FORBID_DOWNLOAD',
    title: 'Cấm tải về tệp gốc',
    description: 'Chỉ cho phép xem trực tuyến, vô hiệu hóa thao tác tải về.',
  },
  {
    id: 'ob-no-cache',
    type: 'NO_CACHE',
    title: 'Không lưu bộ đệm trên thiết bị',
    description: 'Ngăn trình duyệt và thiết bị trung gian lưu bản sao tài liệu.',
  },
] as const;

export function ObligationsPanel({
  obligations,
  onToggleObligation,
  onSetSessionMinutes,
  onSessionMinutesDraftChange,
}: ObligationsPanelProps) {
  const hasObligation = (type: string) => obligations.some((o) => o.type === type);
  const sessionObligation = obligations.find(
    (o): o is Extract<VisualObligation, { type: 'MAX_SESSION_MINUTES' }> =>
      o.type === 'MAX_SESSION_MINUTES',
  );
  const committedMinutes = sessionObligation
    ? clampSessionMinutes(sessionObligation.minutes, DEFAULT_SESSION_MINUTES)
    : DEFAULT_SESSION_MINUTES;

  const [draftMinutes, setDraftMinutes] = useState<string>(() => String(committedMinutes));
  const [syncedMinutes, setSyncedMinutes] = useState<number>(committedMinutes);

  if (syncedMinutes !== committedMinutes) {
    setSyncedMinutes(committedMinutes);
    setDraftMinutes(String(committedMinutes));
  }

  return (
    <div className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
      <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
        <div className="flex items-center gap-2">
          <FileCheck2 size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          <h3 className="font-bold text-xs text-[#222222]">Nghĩa vụ và ràng buộc đi kèm</h3>
        </div>
        <Badge variant="success">Tự động thực thi</Badge>
      </div>

      <p className="text-xs text-[#717171]">
        Các biện pháp bảo mật hệ thống tự động áp dụng khi quy tắc có hiệu lực.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
        {BOOLEAN_OBLIGATION_CARDS.map((item) => (
          <div
            key={item.type}
            className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] hover:bg-[#f7f7f7]"
          >
            <input
              id={item.id}
              type="checkbox"
              checked={hasObligation(item.type)}
              onChange={() => onToggleObligation(item.type)}
              className="h-4 w-4 mt-0.5 rounded border-[#dddddd] accent-[#FF385C] cursor-pointer"
            />
            <div className="flex-1">
              <label htmlFor={item.id} className="font-bold text-[#222222] block cursor-pointer">
                {item.title}
              </label>
              <span className="text-xs text-[#717171] block">{item.description}</span>
            </div>
          </div>
        ))}

        <div className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] sm:col-span-2">
          <input
            id="ob-max-session-minutes"
            type="checkbox"
            checked={hasObligation('MAX_SESSION_MINUTES')}
            onChange={() => {
              onSessionMinutesDraftChange?.(null);
              onToggleObligation('MAX_SESSION_MINUTES');
            }}
            className="h-4 w-4 mt-1 rounded border-[#dddddd] accent-[#FF385C] cursor-pointer"
          />
          <div className="flex-1 space-y-1">
            <label
              htmlFor="ob-max-session-minutes"
              className="font-bold text-[#222222] block cursor-pointer"
            >
              Giới hạn thời gian phiên
            </label>
            <span className="text-xs text-[#717171] block">
              Tự động thu hồi quyền xem sau số phút chỉ định ({MIN_SESSION_MINUTES}–
              {MAX_SESSION_MINUTES} phút).
            </span>
            {hasObligation('MAX_SESSION_MINUTES') && (
              <div className="flex items-center gap-2 pt-1">
                <Input
                  id="ob-session-minutes-input"
                  aria-label="Số phút tối đa của phiên đọc"
                  type="number"
                  inputMode="numeric"
                  min={MIN_SESSION_MINUTES}
                  max={MAX_SESSION_MINUTES}
                  step={1}
                  value={draftMinutes}
                  onChange={(e) => {
                    const raw = e.target.value;
                    setDraftMinutes(raw);
                    onSessionMinutesDraftChange?.(raw);
                    const parsed = parseSessionMinutesDraft(raw);
                    if (parsed.valid) {
                      setSyncedMinutes(parsed.minutes);
                      onSetSessionMinutes(parsed.minutes);
                    }
                  }}
                  onBlur={() => {
                    const normalized = normalizeSessionMinutesDraftOnBlur(
                      draftMinutes,
                      committedMinutes,
                    );
                    setDraftMinutes(String(normalized));
                    setSyncedMinutes(normalized);
                    onSessionMinutesDraftChange?.(null);
                    if (!sessionObligation || sessionObligation.minutes !== normalized) {
                      onSetSessionMinutes(normalized);
                    }
                  }}
                  className="w-24 min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd]"
                />
                <label htmlFor="ob-session-minutes-input" className="text-xs text-[#717171]">
                  phút
                </label>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
