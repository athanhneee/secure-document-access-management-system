'use client';

import { FileCheck2 } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import type { VisualObligation } from './abac-models';

interface ObligationsPanelProps {
  obligations: VisualObligation[];
  onToggleObligation: (type: string) => void;
  onSetSessionMinutes: (minutes: number) => void;
}

const BOOLEAN_OBLIGATION_CARDS = [
  {
    id: 'ob-require-watermark',
    type: 'REQUIRE_WATERMARK',
    title: 'Đóng Thủy Ấn (Watermark)',
    description: 'Nhúng tên, IP, thời gian & mã token lên bản xem tài liệu.',
  },
  {
    id: 'ob-require-mfa',
    type: 'REQUIRE_MFA',
    title: 'Yêu Cầu MFA (FIDO2 / TOTP)',
    description: 'Bắt buộc xác thực đa yếu tố cấp cao trước khi mở.',
  },
  {
    id: 'ob-forbid-download',
    type: 'FORBID_DOWNLOAD',
    title: 'Cấm Tải File (No Download)',
    description: 'Chỉ cho phép xem trực tuyến, vô hiệu hóa nút tải xuống.',
  },
  {
    id: 'ob-no-cache',
    type: 'NO_CACHE',
    title: 'Không Lưu Bộ Đệm (No-Cache)',
    description: 'Gửi header cấm proxy và browser lưu trữ bộ đệm file.',
  },
] as const;

export function ObligationsPanel({
  obligations,
  onToggleObligation,
  onSetSessionMinutes,
}: ObligationsPanelProps) {
  const hasObligation = (type: string) => obligations.some((o) => o.type === type);

  return (
    <div className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
      <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
        <div className="flex items-center gap-2">
          <FileCheck2 size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          <h3 className="font-bold text-xs text-[#222222]">
            Nghĩa Vụ & Ràng Buộc Bắt Buộc Đi Kèm (Policy Obligations)
          </h3>
        </div>
        <Badge variant="success">PDP Enforcement</Badge>
      </div>

      <p className="text-[11px] text-[#717171]">
        Các hành động bảo mật mà hệ thống và giao diện bắt buộc phải thực thi ngay khi quy tắc cho
        phép (PERMIT) hoặc từ chối (DENY).
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
              <span className="text-[11px] text-[#717171] block">{item.description}</span>
            </div>
          </div>
        ))}

        <div className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] sm:col-span-2">
          <input
            id="ob-max-session-minutes"
            type="checkbox"
            checked={hasObligation('MAX_SESSION_MINUTES')}
            onChange={() => onToggleObligation('MAX_SESSION_MINUTES')}
            className="h-4 w-4 mt-1 rounded border-[#dddddd] accent-[#FF385C] cursor-pointer"
          />
          <div className="flex-1 space-y-1">
            <label
              htmlFor="ob-max-session-minutes"
              className="font-bold text-[#222222] block cursor-pointer"
            >
              Giới Hạn Thời Gian Phiên (Max Session Time)
            </label>
            <span className="text-[11px] text-[#717171] block">
              Tự động thu hồi quyền xem sau số phút chỉ định:
            </span>
            {hasObligation('MAX_SESSION_MINUTES') && (
              <div className="flex items-center gap-2 pt-1">
                <Input
                  id="ob-session-minutes-input"
                  aria-label="Số phút tối đa của phiên đọc"
                  type="number"
                  min="5"
                  max="240"
                  value={
                    (
                      obligations.find((o) => o.type === 'MAX_SESSION_MINUTES') as
                        { minutes: number } | undefined
                    )?.minutes || 30
                  }
                  onChange={(e) => onSetSessionMinutes(Number(e.target.value))}
                  className="w-24 h-7 text-xs rounded-full border-[#dddddd]"
                />
                <label htmlFor="ob-session-minutes-input" className="text-[11px] text-[#717171]">
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
