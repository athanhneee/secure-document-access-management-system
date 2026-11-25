'use client';

import type { FormEvent } from 'react';
import { Check, Lock, Send } from 'lucide-react';
import { DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Textarea } from '@/components/ui/textarea';

interface IncidentAnalysisFormProps {
  title: string;
  summary: string;
  findings: string;
  impactAssessment: string;
  isClosed: boolean;
  isSaving: boolean;
  isBusy: boolean;
  onTitleChange: (value: string) => void;
  onSummaryChange: (value: string) => void;
  onFindingsChange: (value: string) => void;
  onImpactChange: (value: string) => void;
  onSubmit: (e: FormEvent) => void;
}

/**
 * Thuật toán: Biểu mẫu phân tích nguyên nhân gốc & đánh giá tác động hồ sơ sự cố (`IncidentAnalysisForm`)
 * Mục đích: Tách riêng vùng chỉnh sửa nội dung phân tích sự cố SOC, khóa nhập liệu khi hồ sơ đã `CLOSED`.
 */
export function IncidentAnalysisForm({
  title,
  summary,
  findings,
  impactAssessment,
  isClosed,
  isSaving,
  isBusy,
  onTitleChange,
  onSummaryChange,
  onFindingsChange,
  onImpactChange,
  onSubmit,
}: IncidentAnalysisFormProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-3">
      <div className="space-y-1">
        <label htmlFor="inc-detail-title" className="font-medium text-[#222222]">
          Tiêu đề sự cố <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="inc-detail-title"
          disabled={isClosed}
          value={title}
          onChange={(e) => onTitleChange(e.target.value)}
          className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd]"
        />
      </div>
      <div className="space-y-1">
        <label htmlFor="inc-detail-summary" className="font-medium text-[#222222]">
          Tóm tắt diễn biến <span className="text-[#C13515]">*</span>
        </label>
        <Textarea
          id="inc-detail-summary"
          rows={2}
          disabled={isClosed}
          value={summary}
          onChange={(e) => onSummaryChange(e.target.value)}
          className="text-xs rounded-[16px] border-[#dddddd]"
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor="inc-detail-findings" className="font-medium text-[#222222]">
            Phân tích / Nguyên nhân gốc
          </label>
          <Textarea
            id="inc-detail-findings"
            rows={3}
            disabled={isClosed}
            value={findings}
            onChange={(e) => onFindingsChange(e.target.value)}
            placeholder="Kết quả điều tra nhật ký, watermark bảo mật, nguồn rò rỉ…"
            className="text-xs rounded-[16px] border-[#dddddd]"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="inc-detail-impact" className="font-medium text-[#222222]">
            Đánh giá mức độ tác động
          </label>
          <Textarea
            id="inc-detail-impact"
            rows={3}
            disabled={isClosed}
            value={impactAssessment}
            onChange={(e) => onImpactChange(e.target.value)}
            placeholder="Phạm vi tài liệu mật và đơn vị bị ảnh hưởng…"
            className="text-xs rounded-[16px] border-[#dddddd]"
          />
        </div>
      </div>
      {!isClosed && (
        <div className="flex justify-end">
          <InteractiveHoverButton
            type="submit"
            variant="secondary"
            size="sm"
            text="Lưu phân tích"
            icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
            isLoading={isSaving}
            disabled={isBusy}
          />
        </div>
      )}
    </form>
  );
}

/**
 * Thuật toán: Chân hộp thoại chuyển trạng thái vòng đời sự cố (`IncidentLifecycleFooter`)
 * Mục đích: Nhập kết luận nghiệm thu khi ở trạng thái `SUBMITTED`/`IN_REVIEW` và kích hoạt trình duyệt / đóng hồ sơ.
 */
export function IncidentLifecycleFooter({
  canSubmit,
  canClose,
  closingNote,
  busyOp,
  onClosingNoteChange,
  onCloseDialog,
  onTransition,
}: {
  canSubmit: boolean;
  canClose: boolean;
  closingNote: string;
  busyOp: 'save' | 'submit' | 'close' | null;
  onClosingNoteChange: (value: string) => void;
  onCloseDialog: () => void;
  onTransition: (mode: 'submit' | 'close') => void;
}) {
  return (
    <>
      {canClose && (
        <div className="space-y-1">
          <label htmlFor="inc-closing-note" className="font-medium text-[#222222]">
            Ghi chú kết luận đóng hồ sơ (không bắt buộc)
          </label>
          <Input
            id="inc-closing-note"
            value={closingNote}
            onChange={(e) => onClosingNoteChange(e.target.value)}
            placeholder="Nhập kết luận nghiệm thu nếu cần (tối thiểu 5 ký tự khi nhập)…"
            className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd]"
          />
        </div>
      )}

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Đóng"
          onClick={onCloseDialog}
        />
        {canSubmit && (
          <InteractiveHoverButton
            type="button"
            variant="primary"
            size="sm"
            text="Gửi phê duyệt"
            icon={<Send size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={busyOp === 'submit'}
            disabled={busyOp !== null}
            onClick={() => onTransition('submit')}
          />
        )}
        {canClose && (
          <InteractiveHoverButton
            type="button"
            variant="primary"
            size="sm"
            text="Đóng hồ sơ sự cố"
            icon={<Lock size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={busyOp === 'close'}
            disabled={busyOp !== null}
            onClick={() => onTransition('close')}
          />
        )}
      </DialogFooter>
    </>
  );
}
