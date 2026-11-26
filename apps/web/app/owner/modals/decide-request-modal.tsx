'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, Clock, Download, Eye, Lock } from 'lucide-react';
import {
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  buildAccessDurationPresets,
  formatRetentionDateVi,
} from '@sda/contracts';
import { Input } from '@/components/ui/input';
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
import { formatGrantPermissionSummary } from '../grant-helpers';
import { inferAllowDownloadFromClassificationCode } from '../helpers';
import type { RequestApprovalDocumentMeta } from '../hooks/use-owner-requests';
import type { AccessRequestItem } from '../types';

interface DecideRequestModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  request: AccessRequestItem | null;
  docMeta?: RequestApprovalDocumentMeta | undefined;
  grantAction: 'VIEW' | 'DOWNLOAD';
  onActionChange: (action: 'VIEW' | 'DOWNLOAD') => void;
  grantValidDays: number;
  onValidDaysChange: (days: number) => void;
  grantValidUntilOverride?: string | null | undefined;
  onValidUntilOverrideChange?: ((untilIso: string | null) => void) | undefined;
  approveNote?: string | undefined;
  onApproveNoteChange?: ((note: string) => void) | undefined;
  isApproving: boolean;
  onConfirmApprove: () => void;
}

/**
 * Thuật toán: Hộp Thoại Phê Duyệt Yêu Cầu Truy Cập Linh Hoạt Số Ngày & Khóa Đóng Khi Đang Xử Lý (`DecideRequestModal`, BUG-102)
 */
export function DecideRequestModal({
  open,
  onOpenChange,
  request,
  docMeta,
  grantAction,
  onActionChange,
  grantValidDays,
  onValidDaysChange,
  grantValidUntilOverride = null,
  onValidUntilOverrideChange,
  approveNote = '',
  onApproveNoteChange,
  isApproving,
  onConfirmApprove,
}: DecideRequestModalProps) {
  const [draftDaysInput, setDraftDaysInput] = useState<{
    requestId: string | undefined;
    raw: string;
  } | null>(null);

  const retentionUntil = docMeta?.retentionUntil ?? request?.documentRetentionUntil ?? null;
  const defaultViewDays = docMeta?.defaultViewDays ?? request?.documentDefaultViewDays ?? null;
  const allowDownload =
    docMeta?.allowDownload ??
    request?.documentAllowDownload ??
    inferAllowDownloadFromClassificationCode(request?.documentClassificationCode);
  const existingGrant = request?.existingActiveGrant ?? null;

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isApproving) return;
    if (!nextOpen) {
      setDraftDaysInput(null);
    }
    onOpenChange(nextOpen);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!isApproveBlocked) {
      onConfirmApprove();
    }
  }

  const durationInputValue = grantValidUntilOverride
    ? ''
    : draftDaysInput && draftDaysInput.requestId === request?.id
      ? draftDaysInput.raw
      : grantValidDays > 0
        ? String(grantValidDays)
        : '';

  const now = new Date();
  const plan = buildAccessDurationPresets({
    maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
    retentionUntil,
    defaultViewDays,
    existingGrantValidUntil: existingGrant?.validUntil ?? null,
    intent:
      existingGrant &&
      request?.requestedAction === 'DOWNLOAD' &&
      !existingGrant.permissions.includes('DOWNLOAD')
        ? 'UPGRADE_DOWNLOAD'
        : 'NEW',
    now,
  });

  const maxAllowedDays = plan.ceiling.maxWholeDays;
  const isRetentionExpired = plan.ceiling.isRetentionExpired;
  const retentionLabelVi = formatRetentionDateVi(retentionUntil);
  const existingPermSummary = existingGrant
    ? formatGrantPermissionSummary(existingGrant.permissions)
    : null;
  const effectiveAction = grantAction === 'DOWNLOAD' && !allowDownload ? 'VIEW' : grantAction;

  const daysValidationError = (() => {
    if (isRetentionExpired) {
      return `Tài liệu đã quá thời hạn lưu trữ bảo mật (${retentionLabelVi}) nên không thể phê duyệt cấp quyền mới.`;
    }
    if (grantValidUntilOverride) {
      const overrideMs = Date.parse(grantValidUntilOverride);
      if (Number.isNaN(overrideMs) || overrideMs <= now.getTime()) {
        return 'Thời điểm kết thúc hiệu lực không hợp lệ.';
      }
      if (overrideMs > plan.ceiling.maxUntil.getTime()) {
        return retentionLabelVi
          ? `Thời điểm kết thúc không được vượt quá hạn lưu trữ tài liệu (${retentionLabelVi}).`
          : `Thời hạn hiệu lực không được vượt quá ${DEFAULT_GRANT_MAX_DURATION_DAYS} ngày.`;
      }
      return null;
    }
    if (maxAllowedDays === 0) {
      return `Tài liệu chỉ còn hiệu lực trong ngày ${retentionLabelVi}. Hãy chọn "Đến hết hạn" để cấp quyền tới cuối ngày.`;
    }
    if (!Number.isInteger(grantValidDays) || grantValidDays < 1) {
      return 'Số ngày hiệu lực phải là số nguyên tối thiểu từ 1 ngày.';
    }
    if (grantValidDays > maxAllowedDays) {
      return plan.ceiling.cappedByRetention && retentionLabelVi
        ? `Số ngày hiệu lực tối đa cho tài liệu này là ${maxAllowedDays} ngày (hạn lưu trữ: ${retentionLabelVi}).`
        : `Số ngày hiệu lực không được vượt quá ${DEFAULT_GRANT_MAX_DURATION_DAYS} ngày.`;
    }
    return null;
  })();

  const isApproveBlocked = isApproving || isRetentionExpired || Boolean(daysValidationError);

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isApproving}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Phê duyệt và cấp quyền truy cập
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Chọn phạm vi quyền truy cập và thời hạn hiệu lực áp dụng cho yêu cầu này.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} noValidate className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Người nhận quyền: <strong className="text-[#222222]">{request?.requestorName}</strong>
            </div>
            <div>
              Tài liệu: <span className="text-[#222222]">{request?.documentTitle}</span>
            </div>
            {request?.requestedFrom && request?.requestedUntil && (
              <div className="text-[#008489] font-medium pt-1 border-t border-[#ebebeb]">
                Thời hạn đề nghị: {formatSafeDateVi(request.requestedFrom, { includeTime: true })}{' '}
                đến {formatSafeDateVi(request.requestedUntil, { includeTime: true })}
              </div>
            )}
            {(retentionLabelVi || defaultViewDays) && (
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-1 border-t border-[#ebebeb] text-[#717171]">
                {retentionLabelVi && (
                  <span className="inline-flex items-center gap-1 font-medium text-[#222222]">
                    <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Hạn lưu trữ tài liệu: {retentionLabelVi}</span>
                  </span>
                )}
                {defaultViewDays && <span>Mặc định mức mật: {defaultViewDays} ngày</span>}
              </div>
            )}
          </div>

          {existingGrant && existingPermSummary && (
            <output className="rounded-[18px] border border-[#ebebeb] bg-[#f7f7f7] p-3 flex items-start gap-2 text-xs text-[#222222]">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#E07912] mt-0.5"
                aria-hidden="true"
              />
              <div className="space-y-0.5 leading-relaxed">
                <div className="font-semibold text-[#222222]">
                  Người yêu cầu đang có quyền hiện hành ({existingPermSummary.label})
                </div>
                <p className="text-[#717171]">
                  Hiệu lực hiện tại đến{' '}
                  <strong className="text-[#222222]">
                    {formatSafeDateVi(existingGrant.validUntil, { includeTime: true })}
                  </strong>
                  . Chọn &ldquo;Giữ hạn hiện có&rdquo; nếu chỉ muốn nâng quyền tải mà không kéo dài
                  thời hạn.
                </p>
              </div>
            </output>
          )}

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">Phạm vi quyền cấp</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                disabled={isApproving}
                aria-pressed={effectiveAction === 'VIEW'}
                onClick={() => onActionChange('VIEW')}
                className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold cursor-pointer ${
                  effectiveAction === 'VIEW'
                    ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd]'
                }`}
              >
                <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Chỉ xem</span>
              </button>
              <button
                type="button"
                aria-pressed={effectiveAction === 'DOWNLOAD'}
                disabled={!allowDownload || isApproving}
                onClick={() => {
                  if (allowDownload) onActionChange('DOWNLOAD');
                }}
                className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold ${
                  !allowDownload
                    ? 'border-[#ebebeb] bg-[#f7f7f7] text-[#b0b0b0] cursor-not-allowed'
                    : effectiveAction === 'DOWNLOAD'
                      ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs cursor-pointer'
                      : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] cursor-pointer'
                }`}
              >
                <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xem &amp; Tải về</span>
              </button>
            </div>
            {!allowDownload && (
              <p className="flex items-center gap-1.5 text-xs text-[#717171] pt-0.5">
                <Lock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>Mức độ mật của tài liệu này không cho phép cấp quyền tải về.</span>
              </p>
            )}
          </fieldset>

          {!isRetentionExpired && (
            <fieldset className="space-y-2 border-0 p-0 m-0 min-w-0">
              <legend className="font-medium text-[#222222] block mb-1">
                Thời hạn hiệu lực cấp quyền
              </legend>

              {plan.options.length > 0 && (
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                  {plan.options.map((opt) => {
                    const isSelected =
                      opt.mode === 'DAYS'
                        ? !grantValidUntilOverride && grantValidDays === opt.days
                        : Boolean(
                            grantValidUntilOverride && opt.untilIso === grantValidUntilOverride,
                          );
                    return (
                      <button
                        key={opt.key}
                        type="button"
                        disabled={isApproving}
                        aria-pressed={isSelected}
                        onClick={() => {
                          setDraftDaysInput(null);
                          if (opt.mode === 'DAYS' && typeof opt.days === 'number') {
                            onValidUntilOverrideChange?.(null);
                            onValidDaysChange(opt.days);
                          } else if (opt.untilIso) {
                            onValidUntilOverrideChange?.(opt.untilIso);
                          }
                        }}
                        className={`min-h-11 sm:min-h-9 px-2.5 py-1.5 rounded-full border text-xs font-semibold transition-all cursor-pointer ${
                          isSelected
                            ? 'border-transparent bg-[#FF385C] text-[#ffffff] shadow-xs'
                            : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                        }`}
                      >
                        {opt.label.replace(' (mặc định)', '')}
                      </button>
                    );
                  })}
                </div>
              )}

              {maxAllowedDays >= 1 && (
                <div className="space-y-1">
                  <label htmlFor="grant-duration" className="text-xs text-[#717171] block">
                    Hoặc nhập số ngày cụ thể (1–{maxAllowedDays} ngày)
                  </label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="grant-duration"
                      type="number"
                      min={1}
                      max={maxAllowedDays}
                      step={1}
                      disabled={isApproving}
                      value={durationInputValue}
                      placeholder={
                        grantValidUntilOverride
                          ? 'Đang dùng mốc thời điểm cụ thể ở trên'
                          : `Nhập số ngày (1–${maxAllowedDays})`
                      }
                      onChange={(e) => {
                        const raw = e.target.value;
                        setDraftDaysInput({ requestId: request?.id, raw });
                        onValidUntilOverrideChange?.(null);
                        if (raw.trim() === '') {
                          onValidDaysChange(0);
                          return;
                        }
                        if (!/^\d+$/u.test(raw.trim())) {
                          onValidDaysChange(0);
                          return;
                        }
                        const parsed = Number(raw.trim());
                        onValidDaysChange(Number.isInteger(parsed) && parsed > 0 ? parsed : 0);
                      }}
                      className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
                    />
                    <span className="text-xs text-[#717171] whitespace-nowrap">
                      Tối đa {maxAllowedDays} ngày
                    </span>
                  </div>
                </div>
              )}

              {grantValidUntilOverride && !daysValidationError && (
                <p className="text-xs text-[#008489] font-medium">
                  Đang áp dụng mốc hiệu lực đến:{' '}
                  {formatSafeDateVi(grantValidUntilOverride, { includeTime: true })}
                </p>
              )}
            </fieldset>
          )}

          {onApproveNoteChange && (
            <div className="space-y-1">
              <label htmlFor="approve-decision-note" className="font-medium text-[#222222]">
                Ghi chú phản hồi (tùy chọn)
              </label>
              <Textarea
                id="approve-decision-note"
                rows={2}
                maxLength={1000}
                disabled={isApproving}
                value={approveNote}
                onChange={(e) => onApproveNoteChange(e.target.value)}
                placeholder="Hướng dẫn sử dụng hoặc lưu ý bảo mật cho người nhận quyền…"
                className="text-xs rounded-[18px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
              />
            </div>
          )}

          {daysValidationError && (
            <p role="alert" className="text-xs font-medium text-[#C13515]">
              {daysValidationError}
            </p>
          )}

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isApproving}
              onClick={() => handleDialogOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Xác nhận cấp quyền"
              disabled={isApproveBlocked}
              isLoading={isApproving}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
