'use client';

import { useState } from 'react';
import { AlertTriangle, Clock, Download, Eye } from 'lucide-react';
import {
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  buildAccessDurationPresets,
  formatRetentionDateVi,
} from '@sda/contracts';
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
import { formatSafeDateVi } from '@/lib/ui-labels';
import { formatLocalDateTimeMin, validateCustomRequestWindow } from '../helpers';
import type { useReaderCatalog } from '../hooks/use-reader-catalog';

interface RequestAccessModalProps {
  catalog: ReturnType<typeof useReaderCatalog>;
  canDownloadDocument?: boolean;
}

/**
 * Thuật toán: Biểu Mẫu Đề Xuất Quyền Truy Cập Ràng Buộc Trần Lưu Trữ, Khóa Đóng Khi Đang Gửi & Cố Định Mốc `min` (`RequestAccessModal`, BUG-102)
 * Mục đích:
 *   - Tự động ẩn mọi mốc chọn nhanh vượt quá `retentionUntil` hoặc trần 30 ngày (`GRANT_MAX_DURATION_DAYS`), gợi ý mặc định theo `default_view_days` của mức độ mật.
 *   - Cố định mốc thời gian mở hộp thoại (`openedAt`) để thuộc tính `min` của `datetime-local` không dịch chuyển khi người dùng đang gõ lý do.
 *   - Khóa đóng hộp thoại (`showClose={!isSubmittingRequest}`, chặn `Escape`/nền mờ/Hủy) khi đang gửi yêu cầu (`BUG-102`) và áp `noValidate` + `maxLength={1000}`.
 */
export function RequestAccessModal({
  catalog,
  canDownloadDocument = true,
}: RequestAccessModalProps) {
  const {
    requestModalOpen,
    setRequestModalOpen,
    targetDoc,
    requestedAction,
    setRequestedAction,
    justification,
    setJustification,
    setRequestDurationDays,
    requestPresetKey,
    setRequestPresetKey,
    setRequestExplicitUntilIso,
    requestExistingGrantUntil,
    requestIntent,
    isCustomDuration,
    setIsCustomDuration,
    customRequestedFrom,
    setCustomRequestedFrom,
    customRequestedUntil,
    setCustomRequestedUntil,
    isSubmittingRequest,
    handleSubmitRequest,
  } = catalog;

  const [modalSnapshot, setModalSnapshot] = useState<{ open: boolean; now: Date }>(() => ({
    open: requestModalOpen,
    now: new Date(),
  }));
  if (requestModalOpen !== modalSnapshot.open) {
    setModalSnapshot({ open: requestModalOpen, now: new Date() });
  }
  const now = modalSnapshot.now;

  const durationPlan = buildAccessDurationPresets({
    maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
    retentionUntil: targetDoc?.retentionUntil,
    defaultViewDays: targetDoc?.defaultViewDays,
    classificationCode: targetDoc?.classificationCode,
    existingGrantValidUntil: requestExistingGrantUntil,
    intent: requestIntent,
    now,
  });

  const minDateTimeLocal = formatLocalDateTimeMin(now);
  const maxDateTimeLocal = formatLocalDateTimeMin(durationPlan.ceiling.maxUntil);
  const customWindowError = isCustomDuration
    ? validateCustomRequestWindow(true, customRequestedFrom, customRequestedUntil, now.getTime(), {
        maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
        retentionUntil: targetDoc?.retentionUntil,
      })
    : null;
  const trimmedLength = justification.trim().length;
  const isRetentionExpired = durationPlan.ceiling.isRetentionExpired;
  const retentionLabelVi = formatRetentionDateVi(targetDoc?.retentionUntil);
  const isSubmitDisabled =
    isSubmittingRequest ||
    isRetentionExpired ||
    trimmedLength < 10 ||
    trimmedLength > 1000 ||
    Boolean(customWindowError) ||
    (!isCustomDuration && !requestPresetKey);

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen && isSubmittingRequest) {
      return;
    }
    setRequestModalOpen(nextOpen);
  }

  return (
    <Dialog open={requestModalOpen} onOpenChange={handleOpenChange}>
      <DialogContent
        showClose={!isSubmittingRequest}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Gửi yêu cầu quyền truy cập tài liệu
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Nêu rõ lý do công việc để chủ sở hữu tài liệu xem xét phê duyệt.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmitRequest} noValidate className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
            <div className="text-[#717171]">Tài liệu yêu cầu</div>
            <div className="font-semibold text-[#222222]">{targetDoc?.title}</div>
            {targetDoc && (
              <div className="pt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
                <ClassificationBadge level={targetDoc.classificationCode} size="sm" />
                {retentionLabelVi && (
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-[#222222]">
                    <Clock
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#717171]"
                      aria-hidden="true"
                    />
                    <span>Hạn tài liệu: {retentionLabelVi}</span>
                  </span>
                )}
              </div>
            )}
            {requestExistingGrantUntil && (
              <div className="pt-1 border-t border-[#ebebeb] text-xs text-[#008489] font-medium">
                Quyền hiện có hiệu lực đến:{' '}
                {formatSafeDateVi(requestExistingGrantUntil, { includeTime: true })}
              </div>
            )}
          </div>

          {isRetentionExpired && (
            <div
              role="alert"
              className="rounded-[18px] border border-[#ebebeb] bg-[#f7f7f7] p-3 flex items-start gap-2 text-xs text-[#C13515]"
            >
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <span>
                Tài liệu đã quá thời hạn lưu trữ bảo mật ({retentionLabelVi}) nên không thể gửi yêu
                cầu truy cập mới.
              </span>
            </div>
          )}

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0" disabled={isSubmittingRequest}>
            <legend className="font-medium text-[#222222] block mb-1">Mức quyền yêu cầu</legend>
            <div
              className={`grid grid-cols-1 gap-2 ${targetDoc?.allowDownload && canDownloadDocument ? 'sm:grid-cols-2' : ''}`}
            >
              <button
                type="button"
                aria-pressed={requestedAction === 'VIEW'}
                disabled={isSubmittingRequest}
                onClick={() => setRequestedAction('VIEW')}
                className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer disabled:opacity-60 ${
                  requestedAction === 'VIEW'
                    ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                }`}
              >
                <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Chỉ xem trực tuyến</span>
              </button>
              {Boolean(targetDoc?.allowDownload) && canDownloadDocument && (
                <button
                  type="button"
                  aria-pressed={requestedAction === 'DOWNLOAD'}
                  disabled={isSubmittingRequest}
                  onClick={() => setRequestedAction('DOWNLOAD')}
                  className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer disabled:opacity-60 ${
                    requestedAction === 'DOWNLOAD'
                      ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs'
                      : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                  }`}
                >
                  <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Xem &amp; Tải về</span>
                </button>
              )}
            </div>
          </fieldset>

          {!isRetentionExpired && (
            <fieldset
              className="space-y-1.5 border-0 p-0 m-0 min-w-0"
              disabled={isSubmittingRequest}
            >
              <legend className="font-medium text-[#222222] block mb-1.5">
                Thời hạn sử dụng mong muốn
              </legend>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                {durationPlan.options.map((opt) => (
                  <button
                    key={opt.key}
                    type="button"
                    aria-pressed={!isCustomDuration && requestPresetKey === opt.key}
                    disabled={isSubmittingRequest}
                    onClick={() => {
                      setRequestPresetKey(opt.key);
                      setRequestDurationDays(
                        opt.days ?? Math.max(1, durationPlan.recommendedDays || 1),
                      );
                      setRequestExplicitUntilIso(opt.untilIso ?? null);
                      setIsCustomDuration(false);
                    }}
                    className={`min-h-11 sm:min-h-9 px-2.5 py-1.5 rounded-full border text-xs font-semibold transition-all cursor-pointer disabled:opacity-60 ${
                      !isCustomDuration && requestPresetKey === opt.key
                        ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs'
                        : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <p className="text-xs text-[#717171]">
                {durationPlan.ceiling.cappedByRetention && retentionLabelVi
                  ? `Giới hạn theo hạn lưu trữ tài liệu (tối đa đến ${retentionLabelVi}, không vượt quá ${DEFAULT_GRANT_MAX_DURATION_DAYS} ngày).`
                  : `Thời hạn đề nghị tối đa ${DEFAULT_GRANT_MAX_DURATION_DAYS} ngày (mặc định mức độ mật này: ${durationPlan.policyDefaultDays} ngày).`}
              </p>

              <div className="pt-0.5">
                <button
                  type="button"
                  disabled={isSubmittingRequest}
                  onClick={() => setIsCustomDuration(!isCustomDuration)}
                  className="min-h-11 sm:min-h-8 inline-flex items-center rounded-full px-2 py-1 text-xs text-[#008489] hover:underline font-medium cursor-pointer disabled:opacity-60"
                >
                  {isCustomDuration ? 'Chọn thời hạn nhanh' : 'Tùy chọn khoảng thời gian cụ thể'}
                </button>
              </div>

              {isCustomDuration && (
                <div className="space-y-2 pt-1">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                      <label
                        htmlFor="custom-requested-from"
                        className="text-xs text-[#717171] block mb-0.5"
                      >
                        Từ thời điểm
                      </label>
                      <input
                        id="custom-requested-from"
                        type="datetime-local"
                        required
                        disabled={isSubmittingRequest}
                        min={minDateTimeLocal}
                        max={maxDateTimeLocal}
                        value={customRequestedFrom}
                        onChange={(e) => setCustomRequestedFrom(e.target.value)}
                        className="w-full min-h-11 sm:h-9 text-xs px-3 py-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15"
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="custom-requested-until"
                        className="text-xs text-[#717171] block mb-0.5"
                      >
                        Đến thời điểm
                      </label>
                      <input
                        id="custom-requested-until"
                        type="datetime-local"
                        required
                        disabled={isSubmittingRequest}
                        min={customRequestedFrom || minDateTimeLocal}
                        max={maxDateTimeLocal}
                        value={customRequestedUntil}
                        onChange={(e) => setCustomRequestedUntil(e.target.value)}
                        className="w-full min-h-11 sm:h-9 text-xs px-3 py-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15"
                      />
                    </div>
                  </div>
                  {customWindowError && (
                    <p className="text-xs text-[#C13515] font-medium">{customWindowError}</p>
                  )}
                </div>
              )}
            </fieldset>
          )}

          <div className="space-y-1">
            <label htmlFor="req-justification" className="font-medium text-[#222222]">
              Lý do đề xuất truy cập <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="req-justification"
              required
              rows={3}
              maxLength={1000}
              disabled={isSubmittingRequest}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Mô tả nhiệm vụ hoặc dự án cụ thể cần sử dụng tài liệu này…"
              className="text-xs bg-[#f7f7f7] border-[#ebebeb] text-[#222222]"
            />
            <p className="text-xs text-[#717171]">
              {trimmedLength < 10
                ? `Cần thêm ${10 - trimmedLength} ký tự (tối thiểu 10, tối đa 1000 ký tự).`
                : `Đã đạt yêu cầu (${trimmedLength} / 1000 ký tự).`}
            </p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isSubmittingRequest}
              onClick={() => handleOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Gửi yêu cầu"
              disabled={isSubmitDisabled}
              isLoading={isSubmittingRequest}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
