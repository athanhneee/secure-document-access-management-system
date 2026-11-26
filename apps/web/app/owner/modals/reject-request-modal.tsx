'use client';

import type { FormEvent } from 'react';
import { XCircle } from 'lucide-react';
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
import type { AccessRequestItem } from '../types';

interface RejectRequestModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  request: AccessRequestItem | null;
  decisionNote: string;
  onDecisionNoteChange: (note: string) => void;
  isRejecting: boolean;
  onSubmit: (e: FormEvent) => void;
}

/**
 * Thuật toán: Hộp Thoại Từ Chối Yêu Cầu Truy Cập Kèm Lý Do Tường Minh (`RejectRequestModal`, BUG-102)
 * Thay thế hộp thoại xác nhận cứng bằng biểu mẫu nhập `decisionNote` (`maxLength={1000}`) gửi cho người yêu cầu và lưu nhật ký kiểm toán.
 */
export function RejectRequestModal({
  open,
  onOpenChange,
  request,
  decisionNote,
  onDecisionNoteChange,
  isRejecting,
  onSubmit,
}: RejectRequestModalProps) {
  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isRejecting) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isRejecting}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <div className="flex items-center gap-2 text-[#C13515]">
            <XCircle size={20} strokeWidth={1.75} aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Từ chối yêu cầu truy cập
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Nhập lý do từ chối để thông báo rõ cho người yêu cầu và lưu vào nhật ký kiểm toán.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} noValidate className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Người yêu cầu: <strong className="text-[#222222]">{request?.requestorName}</strong> (
              {request?.requestorDepartment})
            </div>
            <div>
              Tài liệu: <span className="text-[#222222]">{request?.documentTitle}</span>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="reject-decision-note" className="font-medium text-[#222222]">
              Lý do từ chối <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="reject-decision-note"
              required
              disabled={isRejecting}
              maxLength={1000}
              rows={3}
              value={decisionNote}
              onChange={(e) => onDecisionNoteChange(e.target.value)}
              placeholder="Ví dụ: Chưa kèm mã hồ sơ dự án hoặc phạm vi công việc chưa phù hợp…"
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0]"
            />
            <p className="text-[11px] text-[#717171] tabular-nums">
              {decisionNote.trim().length} / 1000 ký tự
            </p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isRejecting}
              onClick={() => handleDialogOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="danger"
              size="sm"
              text="Xác nhận từ chối"
              disabled={isRejecting || !decisionNote.trim()}
              isLoading={isRejecting}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
