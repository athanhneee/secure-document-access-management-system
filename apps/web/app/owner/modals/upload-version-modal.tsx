'use client';

import type { FormEvent } from 'react';
import { AlertTriangle, CheckCircle2, Layers } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { validateUploadFileInput } from '../helpers';
import type { DocumentItem } from '../types';

interface UploadVersionModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  newVersionFile: File | null;
  onFileChange: (file: File | null) => void;
  newVersionNote: string;
  onNoteChange: (note: string) => void;
  isUploading: boolean;
  onSubmit: (e: FormEvent) => void;
}

export function UploadVersionModal({
  open,
  onOpenChange,
  document,
  newVersionFile,
  onFileChange,
  newVersionNote,
  onNoteChange,
  isUploading,
  onSubmit,
}: UploadVersionModalProps) {
  const fileError = newVersionFile ? validateUploadFileInput(newVersionFile) : null;

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isUploading) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isUploading}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Layers size={20} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Tải lên phiên bản mới
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Tải lên tệp mới (tối đa 50 MB) để tạo phiên bản cập nhật cho tài liệu &quot;
            {document?.title}&quot;.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} noValidate className="space-y-3.5 py-2 text-xs">
          <div className="space-y-1">
            <label htmlFor="new-version-file" className="font-medium text-[#222222]">
              Chọn tệp phiên bản mới <span className="text-[#C13515]">*</span>
            </label>
            <input
              id="new-version-file"
              type="file"
              required
              disabled={isUploading}
              accept=".pdf,.docx,.xlsx,.pptx"
              onChange={(e) => onFileChange(e.target.files?.[0] || null)}
              className="w-full text-xs text-[#717171] file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-[#f7f7f7] file:text-xs file:font-medium file:text-[#222222] hover:file:bg-[#ebebeb] cursor-pointer disabled:opacity-60"
            />
            {newVersionFile &&
              (fileError ? (
                <div role="alert" className="flex items-start gap-1.5 pt-1 text-xs text-[#C13515]">
                  <AlertTriangle
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0 mt-0.5"
                    aria-hidden="true"
                  />
                  <span>{fileError}</span>
                </div>
              ) : (
                <div className="flex items-center gap-1.5 pt-1 text-xs text-[#008A05]">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    <strong className="text-[#222222]">{newVersionFile.name}</strong> (
                    {(newVersionFile.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
              ))}
          </div>

          <div className="space-y-1">
            <label htmlFor="new-version-note" className="font-medium text-[#222222]">
              Ghi chú thay đổi
            </label>
            <Input
              id="new-version-note"
              maxLength={500}
              disabled={isUploading}
              value={newVersionNote}
              onChange={(e) => onNoteChange(e.target.value)}
              placeholder="Ví dụ: Bổ sung phụ lục giải trình tài chính…"
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
            />
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isUploading}
              onClick={() => handleDialogOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Tải lên phiên bản"
              disabled={isUploading || !newVersionFile || Boolean(fileError)}
              isLoading={isUploading}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
