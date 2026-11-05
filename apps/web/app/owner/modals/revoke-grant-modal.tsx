'use client';

import type { FormEvent } from 'react';
import { AlertOctagon } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import type { AccessGrantItem } from '../types';

interface RevokeGrantModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  grant: AccessGrantItem | null;
  revokeReason: string;
  onReasonChange: (reason: string) => void;
  isRevoking: boolean;
  onSubmit: (e: FormEvent) => void;
}

export function RevokeGrantModal({
  open,
  onOpenChange,
  grant,
  revokeReason,
  onReasonChange,
  isRevoking,
  onSubmit,
}: RevokeGrantModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border border-[#C13515]/20 bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center gap-2 text-[#C13515]">
            <AlertOctagon size={20} strokeWidth={1.75} aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#C13515]">
              Thu hồi giấy phép truy cập khẩn cấp
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            D-BR15: Bắt buộc nêu rõ lý do thu hồi (ít nhất 10 ký tự). Mọi phiên làm việc đang chạy
            sẽ bị ngắt lập tức.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-3.5 py-2">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 text-xs space-y-1">
            <div>
              Đối tượng: <strong className="text-[#222222]">{grant?.principalName}</strong>
            </div>
            <div>
              Tài liệu: <span className="text-[#222222]">{grant?.documentTitle}</span>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="revoke-reason" className="text-xs font-medium text-[#222222]">
              Lý do thu hồi (Ghi vào Audit Trail) <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="revoke-reason"
              required
              rows={3}
              value={revokeReason}
              onChange={(e) => onReasonChange(e.target.value)}
              placeholder="Ví dụ: Dự án đã hoàn thành trước hạn; hoặc có dấu hiệu rò rỉ thông tin..."
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
            />
            <p className="text-[10px] text-[#717171]">
              Tối thiểu 10 ký tự ({revokeReason.trim().length}/10)
            </p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              onClick={() => onOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="danger"
              size="sm"
              text="Xác nhận thu hồi ngay"
              disabled={isRevoking || revokeReason.trim().length < 10}
              isLoading={isRevoking}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
