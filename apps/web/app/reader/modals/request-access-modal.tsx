'use client';

import { Eye, Download } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
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
import type { useReaderCatalog } from '../hooks/use-reader-catalog';

const DURATION_OPTIONS = [
  { days: 3, label: '3 ngày' },
  { days: 7, label: '7 ngày (Chuẩn)' },
  { days: 14, label: '14 ngày' },
  { days: 30, label: '30 ngày' },
] as const;

interface RequestAccessModalProps {
  catalog: ReturnType<typeof useReaderCatalog>;
}

export function RequestAccessModal({ catalog }: RequestAccessModalProps) {
  const {
    requestModalOpen,
    setRequestModalOpen,
    targetDoc,
    requestedAction,
    setRequestedAction,
    justification,
    setJustification,
    requestDurationDays,
    setRequestDurationDays,
    isCustomDuration,
    setIsCustomDuration,
    customRequestedFrom,
    setCustomRequestedFrom,
    customRequestedUntil,
    setCustomRequestedUntil,
    isSubmittingRequest,
    handleSubmitRequest,
  } = catalog;

  return (
    <Dialog open={requestModalOpen} onOpenChange={setRequestModalOpen}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Gửi yêu cầu cấp quyền truy cập tài liệu
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Nêu rõ căn cứ nghiệp vụ để chủ sở hữu tài liệu và hệ thống PDP phê duyệt
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmitRequest} className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
            <div className="text-[#717171]">Tài liệu yêu cầu:</div>
            <div className="font-semibold text-[#222222]">{targetDoc?.title}</div>
            {targetDoc && (
              <div className="pt-1">
                <ClassificationBadge level={targetDoc.classificationCode} size="sm" />
              </div>
            )}
          </div>

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">Mức quyền yêu cầu:</legend>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                aria-pressed={requestedAction === 'VIEW'}
                onClick={() => setRequestedAction('VIEW')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  requestedAction === 'VIEW'
                    ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                }`}
              >
                <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xem trực tuyến (VIEW)</span>
              </button>
              <button
                type="button"
                aria-pressed={requestedAction === 'DOWNLOAD'}
                disabled={!targetDoc?.allowDownload}
                onClick={() => setRequestedAction('DOWNLOAD')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  requestedAction === 'DOWNLOAD'
                    ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                } disabled:opacity-40 disabled:cursor-not-allowed`}
              >
                <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xem &amp; Tải bản sao</span>
              </button>
            </div>
          </fieldset>

          <fieldset className="space-y-1.5 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1.5">
              Thời gian sử dụng mong muốn:
            </legend>
            {/* CONFLICT-RESOLVED: Chuyển bo góc nút chọn thời hạn sang hình viên thuốc rounded-full và màu dấu sao sang #C13515 theo chuẩn ui-design-system.md §4–5 */}
            <div className="grid grid-cols-4 gap-1.5">
              {DURATION_OPTIONS.map((opt) => (
                <button
                  key={opt.days}
                  type="button"
                  aria-pressed={!isCustomDuration && requestDurationDays === opt.days}
                  onClick={() => {
                    setRequestDurationDays(opt.days);
                    setIsCustomDuration(false);
                  }}
                  className={`px-2.5 py-1.5 rounded-full border text-xs font-semibold transition-all cursor-pointer ${
                    !isCustomDuration && requestDurationDays === opt.days
                      ? 'border-[#FF385C] bg-[#FF385C]/15 text-[#FF385C]'
                      : 'border-[#ebebeb] bg-[#f7f7f7] text-[#717171] hover:border-[#dddddd]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            <div className="pt-0.5">
              <button
                type="button"
                onClick={() => setIsCustomDuration(!isCustomDuration)}
                className="rounded-full px-2 py-0.5 text-xs text-[#008489] hover:underline font-medium cursor-pointer"
              >
                {isCustomDuration
                  ? '← Chọn thời hạn nhanh'
                  : 'Tùy chọn khoảng thời gian cụ thể (Từ ngày - Đến ngày) →'}
              </button>
            </div>

            {isCustomDuration && (
              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <label
                    htmlFor="custom-requested-from"
                    className="text-[13px] text-[#717171] block mb-0.5"
                  >
                    Từ ngày:
                  </label>
                  <input
                    id="custom-requested-from"
                    type="datetime-local"
                    value={customRequestedFrom}
                    onChange={(e) => setCustomRequestedFrom(e.target.value)}
                    className="w-full text-xs px-3 py-1.5 rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222]"
                  />
                </div>
                <div>
                  <label
                    htmlFor="custom-requested-until"
                    className="text-[13px] text-[#717171] block mb-0.5"
                  >
                    Đến ngày:
                  </label>
                  <input
                    id="custom-requested-until"
                    type="datetime-local"
                    value={customRequestedUntil}
                    onChange={(e) => setCustomRequestedUntil(e.target.value)}
                    className="w-full text-xs px-3 py-1.5 rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222]"
                  />
                </div>
              </div>
            )}
          </fieldset>

          <div className="space-y-1">
            <label htmlFor="req-justification" className="font-medium text-[#222222]">
              Căn cứ nghiệp vụ / Lý do đề xuất <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="req-justification"
              required
              rows={3}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Mô tả nhiệm vụ hoặc dự án cụ thể cần đối chiếu thông tin này..."
              className="text-xs bg-[#f7f7f7] border-[#ebebeb] text-[#222222]"
            />
            <p className="text-[13px] text-[#717171]">
              Tối thiểu 10 ký tự ({justification.trim().length}/10)
            </p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              onClick={() => setRequestModalOpen(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Gửi yêu cầu"
              disabled={isSubmittingRequest || justification.trim().length < 10}
              isLoading={isSubmittingRequest}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
