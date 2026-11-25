'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, Ban } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Textarea } from '@/components/ui/textarea';
import type { DocumentSessionItem } from '../types';

interface TerminateSessionModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  session: DocumentSessionItem | null;
  isSubmitting: boolean;
  onConfirm: (reason: string) => Promise<boolean>;
  onError: (msg: string) => void;
}

/**
 * Thuật toán: Ngắt Phiên Truy Cập Khẩn Cấp Có Ghi Lý Do Kiểm Toán (`TerminateSessionModal`)
 * Mục đích: Thu thập lý do ngắt phiên (`5..500` ký tự) truyền trong body `POST /access-sessions/:id/terminate` và chỉ đóng `<dialog>` sau khi máy chủ xác nhận thành công.
 */
export function TerminateSessionModal({
  open,
  onOpenChange,
  session,
  isSubmitting,
  onConfirm,
  onError,
}: TerminateSessionModalProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!isSubmitting) onOpenChange(next);
      }}
    >
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <AlertTriangle
              size={20}
              strokeWidth={1.75}
              className="text-[#C13515] shrink-0"
              aria-hidden="true"
            />
            <span>Ngắt phiên đọc tài liệu khẩn cấp</span>
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Phiên đọc trực tuyến sẽ bị chấm dứt ngay lập tức và lý do sẽ được ghi vào nhật ký kiểm
            toán.
          </DialogDescription>
        </DialogHeader>

        {open && session && (
          <TerminateSessionForm
            key={session.id}
            session={session}
            isSubmitting={isSubmitting}
            onClose={() => onOpenChange(false)}
            onConfirm={onConfirm}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function TerminateSessionForm({
  session,
  isSubmitting,
  onClose,
  onConfirm,
  onError,
}: {
  session: DocumentSessionItem;
  isSubmitting: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => Promise<boolean>;
  onError: (msg: string) => void;
}) {
  const [reason, setReason] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = reason.trim();
    if (trimmed.length < 5 || trimmed.length > 500) {
      onError('Lý do ngắt phiên phải có độ dài từ 5 đến 500 ký tự.');
      return;
    }
    const ok = await onConfirm(trimmed);
    if (ok) onClose();
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3.5 py-2 text-xs">
      <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
        <div className="font-semibold text-[#222222]">{session.documentTitle}</div>
        <div className="text-[#717171]">
          Người đọc: <strong className="text-[#222222]">{session.fullName}</strong> (@
          {session.username}) · IP: <span className="font-mono">{session.ipAddress}</span>
        </div>
      </div>

      <div className="space-y-1">
        <label htmlFor="terminate-session-reason" className="font-medium text-[#222222]">
          Lý do ngắt phiên (tối thiểu 5 ký tự) <span className="text-[#C13515]">*</span>
        </label>
        <Textarea
          id="terminate-session-reason"
          required
          minLength={5}
          maxLength={500}
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Ví dụ: Phát hiện truy cập bất thường ngoài giờ làm việc, cần ngắt phiên ngay…"
          className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] focus-visible:border-[#FF385C]"
        />
      </div>

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Hủy"
          disabled={isSubmitting}
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="danger"
          size="sm"
          text="Ngắt phiên ngay"
          icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
          isLoading={isSubmitting}
          disabled={isSubmitting}
        />
      </DialogFooter>
    </form>
  );
}
