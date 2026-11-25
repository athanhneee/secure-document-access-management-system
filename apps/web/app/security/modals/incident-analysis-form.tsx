'use client';

import type { FormEvent } from 'react';
import { Check, Eye, Lock, Send } from 'lucide-react';
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
  isDraftDirty?: boolean | undefined;
  onTitleChange: (value: string) => void;
  onSummaryChange: (value: string) => void;
  onFindingsChange: (value: string) => void;
  onImpactChange: (value: string) => void;
  onSubmit: (e: FormEvent) => void;
}

/**
 * Thuật toán: Biểu mẫu phân tích nguyên nhân gốc & đánh giá tác động hồ sơ sự cố (`IncidentAnalysisForm`)
 * Mục đích: Tách riêng vùng chỉnh sửa nội dung phân tích sự cố SOC, báo hiệu bản nháp chưa lưu và khóa khi hồ sơ đã `CLOSED` hoặc không có quyền `MANAGE`.
 */
export function IncidentAnalysisForm({
  title,
  summary,
  findings,
  impactAssessment,
  isClosed,
  isSaving,
  isBusy,
  isDraftDirty = false,
  onTitleChange,
  onSummaryChange,
  onFindingsChange,
  onImpactChange,
  onSubmit,
}: IncidentAnalysisFormProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-3" noValidate>
      <div className="space-y-1">
        <label htmlFor="inc-detail-title" className="font-medium text-[#222222]">
          Tiêu đề sự cố <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="inc-detail-title"
          disabled={isClosed}
          value={title}
          onChange={(e) => onTitleChange(e.target.value)}
          className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] placeholder:text-[#717171]"
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
          className="text-xs rounded-[16px] border-[#dddddd] placeholder:text-[#717171]"
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
            className="text-xs rounded-[16px] border-[#dddddd] placeholder:text-[#717171]"
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
            className="text-xs rounded-[16px] border-[#dddddd] placeholder:text-[#717171]"
          />
        </div>
      </div>
      {!isClosed && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-[#717171]">
            {isDraftDirty ? 'Bạn có thay đổi phân tích chưa lưu.' : ''}
          </span>
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
 * Thuật toán: Chân Hộp Thoại Chuyển Trạng Thái Vòng Đời Sự Cố (`DRAFT -> SUBMITTED -> IN_REVIEW -> CLOSED`) (`IncidentLifecycleFooter`)
 */
export function IncidentLifecycleFooter({
  canSubmit,
  canReview,
  canClose,
  incompleteActionsCount,
  submittedToOwner,
  submittedToAdmin,
  closingNote,
  forceClose,
  busyOp,
  onSubmittedToOwnerChange,
  onSubmittedToAdminChange,
  onClosingNoteChange,
  onForceCloseChange,
  onCloseDialog,
  onTransition,
}: {
  canSubmit: boolean;
  canReview: boolean;
  canClose: boolean;
  incompleteActionsCount: number;
  submittedToOwner: string;
  submittedToAdmin: string;
  closingNote: string;
  forceClose: boolean;
  busyOp: 'save' | 'submit' | 'review' | 'close' | null;
  onSubmittedToOwnerChange: (value: string) => void;
  onSubmittedToAdminChange: (value: string) => void;
  onClosingNoteChange: (value: string) => void;
  onForceCloseChange: (value: boolean) => void;
  onCloseDialog: () => void;
  onTransition: (mode: 'submit' | 'review' | 'close') => void;
}) {
  return (
    <>
      {canSubmit && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3">
          <div className="space-y-1">
            <label htmlFor="inc-submit-owner" className="font-medium text-[#222222]">
              ID Chủ sở hữu nhận báo cáo (tùy chọn)
            </label>
            <Input
              id="inc-submit-owner"
              value={submittedToOwner}
              onChange={(e) => onSubmittedToOwnerChange(e.target.value)}
              placeholder="VD: 9"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] placeholder:text-[#717171]"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="inc-submit-admin" className="font-medium text-[#222222]">
              ID Quản trị viên nhận báo cáo (tùy chọn)
            </label>
            <Input
              id="inc-submit-admin"
              value={submittedToAdmin}
              onChange={(e) => onSubmittedToAdminChange(e.target.value)}
              placeholder="VD: 8"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] placeholder:text-[#717171]"
            />
          </div>
        </div>
      )}

      {canClose && (
        <div className="space-y-2 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3">
          <div className="space-y-1">
            <label htmlFor="inc-closing-note" className="font-medium text-[#222222]">
              Ghi chú kết luận đóng hồ sơ{' '}
              {incompleteActionsCount > 0 ? '(bắt buộc khi đóng ngoại lệ)' : '(không bắt buộc)'}
            </label>
            <Input
              id="inc-closing-note"
              value={closingNote}
              onChange={(e) => onClosingNoteChange(e.target.value)}
              placeholder="Nhập kết luận nghiệm thu (tối thiểu 5 ký tự khi nhập)…"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] placeholder:text-[#717171]"
            />
          </div>
          {incompleteActionsCount > 0 && (
            <label
              htmlFor="inc-force-close"
              className="flex items-start gap-2 text-xs text-[#222222] cursor-pointer pt-1"
            >
              <input
                id="inc-force-close"
                type="checkbox"
                checked={forceClose}
                onChange={(e) => onForceCloseChange(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[#dddddd] accent-[#FF385C]"
              />
              <span>
                Đóng ngoại lệ dù còn <strong>{incompleteActionsCount}</strong> hành động khắc phục
                chưa hoàn tất (yêu cầu nhập ghi chú kết luận ở trên).
              </span>
            </label>
          )}
        </div>
      )}

      <DialogFooter className="pt-2 flex flex-wrap gap-2">
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
        {canReview && (
          <InteractiveHoverButton
            type="button"
            variant="secondary"
            size="sm"
            text="Chuyển xem xét"
            icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={busyOp === 'review'}
            disabled={busyOp !== null}
            onClick={() => onTransition('review')}
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
