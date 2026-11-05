'use client';

import type { FormEvent } from 'react';
import { Archive } from 'lucide-react';
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
import type { DocumentItem } from '../types';

interface ArchiveDocumentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  archiveReason: string;
  onReasonChange: (reason: string) => void;
  isArchiving: boolean;
  onSubmit: (e: FormEvent) => void;
}

export function ArchiveDocumentModal({
  open,
  onOpenChange,
  document,
  archiveReason,
  onReasonChange,
  isArchiving,
  onSubmit,
}: ArchiveDocumentModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border border-[#C13515]/20 bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center gap-2 text-[#C13515]">
            <Archive size={20} strokeWidth={1.75} aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#C13515]">
              Lưu trữ tài liệu (Archive)
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Tài liệu sẽ bị đóng băng (ARCHIVED). Toàn bộ giấy phép truy cập sẽ bị tạm ngưng và các
            phiên đọc hiện hành sẽ bị ngắt lập tức.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Tài liệu: <strong>{document?.title}</strong>
            </div>
            <div>Mã số: {document?.documentCode}</div>
          </div>

          <div className="space-y-1">
            <label htmlFor="archive-reason" className="font-medium text-[#222222]">
              Lý do lưu trữ
            </label>
            <Textarea
              id="archive-reason"
              rows={3}
              value={archiveReason}
              onChange={(e) => onReasonChange(e.target.value)}
              placeholder="Ví dụ: Tài liệu đã hoàn thành chu kỳ sử dụng và lưu kho an toàn..."
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
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
              text="Xác nhận lưu trữ"
              disabled={isArchiving}
              isLoading={isArchiving}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
