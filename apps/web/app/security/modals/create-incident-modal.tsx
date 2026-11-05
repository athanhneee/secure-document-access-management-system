'use client';

import { useState, type FormEvent } from 'react';
import { FileCheck } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Textarea } from '@/components/ui/textarea';

interface CreateIncidentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function CreateIncidentModal({
  open,
  onOpenChange,
  onClearError,
  onSuccess,
  onError,
}: CreateIncidentModalProps) {
  const [incTitle, setIncTitle] = useState('');
  const [incSummary, setIncSummary] = useState('');
  const [isCreatingInc, setIsCreatingInc] = useState(false);

  async function handleCreateIncident(e: FormEvent) {
    e.preventDefault();
    if (!incTitle.trim() || incSummary.trim().length < 10) {
      onError('Tiêu đề và tóm tắt sự cố (ít nhất 10 ký tự) là bắt buộc.');
      return;
    }

    setIsCreatingInc(true);
    onClearError();
    try {
      await apiClient('/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: incTitle.trim(),
          summary: incSummary.trim(),
        }),
      });

      onOpenChange(false);
      setIncTitle('');
      setIncSummary('');
      await onSuccess('Đã khởi tạo hồ sơ báo cáo sự cố an ninh (trạng thái DRAFT).');
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo báo cáo sự cố.');
      } else {
        onError('Đã xảy ra lỗi khi tạo sự cố.');
      }
    } finally {
      setIsCreatingInc(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Lập hồ sơ sự cố an ninh thông tin mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Ghi nhận sự cố để phục vụ quy trình điều tra, khắc phục và báo cáo lãnh đạo
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleCreateIncident} className="space-y-3.5 py-2 text-xs">
          <div className="space-y-1">
            <label htmlFor="inc-title" className="font-medium text-[#222222]">
              Tiêu đề sự cố <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="inc-title"
              required
              value={incTitle}
              onChange={(e) => setIncTitle(e.target.value)}
              placeholder="Ví dụ: Nghi vấn rò rỉ tài liệu mật phòng Tài chính"
              className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="inc-summary" className="font-medium text-[#222222]">
              Tóm tắt diễn biến & đánh giá tác động <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="inc-summary"
              required
              rows={4}
              value={incSummary}
              onChange={(e) => setIncSummary(e.target.value)}
              placeholder="Mô tả sự việc, các bằng chứng sơ bộ và mức độ rủi ro đối với tổ chức..."
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
            />
            <p className="text-[10px] text-[#717171]">
              Tối thiểu 10 ký tự ({incSummary.trim().length}/10)
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
              variant="primary"
              size="sm"
              text="Tạo hồ sơ DRAFT"
              icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isCreatingInc}
              disabled={isCreatingInc || incSummary.trim().length < 10}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
