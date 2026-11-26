'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, Check, ShieldAlert, ShieldCheck } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { ClassificationBadge } from '@/components/classification-badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { ClearanceOptionRow, UserRow } from '../types';

interface UpdateClearanceModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserRow | null;
  clearanceOptions: ClearanceOptionRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Hộp Thoại Cập Nhật Cấp Độ Thẩm Tra Bell-LaPadula Có Kiểm Soát Tương Tranh OCC (`UpdateClearanceModal`)
 * Mục đích: Cho phép quản trị viên nâng, hạ hoặc thu hồi thuộc tính `CLEARANCE_LEVEL` qua `PUT /users/:id/clearance`, đồng thời cảnh báo thu hồi dây chuyền giấy phép/phiên khi hạ bậc mật.
 */
export function UpdateClearanceModal({
  open,
  onOpenChange,
  user,
  clearanceOptions,
  onClearError,
  onSuccess,
  onError,
}: UpdateClearanceModalProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isSubmitting) return;
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Cấp thẩm quyền bảo mật: @{user?.username}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Thiết lập cấp thẩm quyền truy cập tài liệu mật cho {user?.fullName}.
          </DialogDescription>
        </DialogHeader>

        {open && user && (
          <UpdateClearanceForm
            key={`${user.id}-${user.version}-${user.clearanceOptionId ?? 'none'}`}
            user={user}
            clearanceOptions={clearanceOptions}
            onSubmittingChange={setIsSubmitting}
            onClose={() => onOpenChange(false)}
            onClearError={onClearError}
            onSuccess={onSuccess}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

interface UpdateClearanceFormProps {
  user: UserRow;
  clearanceOptions: ClearanceOptionRow[];
  onSubmittingChange: (submitting: boolean) => void;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function UpdateClearanceForm({
  user,
  clearanceOptions,
  onSubmittingChange,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: UpdateClearanceFormProps) {
  const [selectedOptionId, setSelectedOptionId] = useState(user.clearanceOptionId ?? '');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const currentRank = user.clearanceRank ?? 0;
  const selectedOption = clearanceOptions.find(
    (opt) => String(opt.id) === String(selectedOptionId),
  );
  const nextRank = selectedOption?.rank ?? 0;
  const isDowngrade = nextRank < currentRank;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setIsSubmitting(true);
    onSubmittingChange(true);
    onClearError();

    try {
      const res = await apiClient<{
        clearanceCode?: string | null;
        clearanceName?: string | null;
        clearanceRank?: number;
        revokedGrantsCount?: number;
        terminatedSessionsCount?: number;
      }>(`/users/${user.id}/clearance`, {
        method: 'PUT',
        body: JSON.stringify({
          expectedVersion: user.version,
          clearanceOptionId: selectedOptionId ? selectedOptionId : null,
        }),
      });

      const label = res.clearanceName
        ? `${res.clearanceName} (Cấp ${res.clearanceRank ?? nextRank})`
        : 'Chưa cấp (Cấp 0)';
      const cascadeParts: string[] = [];
      if ((res.revokedGrantsCount ?? 0) > 0) {
        cascadeParts.push(`thu hồi ${res.revokedGrantsCount} quyền truy cập`);
      }
      if ((res.terminatedSessionsCount ?? 0) > 0) {
        cascadeParts.push(`ngắt ${res.terminatedSessionsCount} phiên đọc vượt thẩm quyền`);
      }
      const cascadeNote =
        cascadeParts.length > 0 ? ` — Đã tự động ${cascadeParts.join(' và ')}.` : '.';

      onClose();
      await onSuccess(
        `Đã cập nhật cấp thẩm quyền bảo mật của @${user.username} thành ${label}${cascadeNote}`,
      );
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể cập nhật cấp thẩm quyền bảo mật.'
          : 'Đã xảy ra lỗi khi cập nhật cấp thẩm quyền bảo mật.',
      );
    } finally {
      setIsSubmitting(false);
      onSubmittingChange(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-3.5 py-2 text-xs">
      <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 flex items-center justify-between gap-2">
        <span className="text-[#717171]">Cấp thẩm quyền hiện tại</span>
        {user.clearanceCode ? (
          <ClassificationBadge code={user.clearanceCode} showRank subject="user" size="sm" />
        ) : (
          <span className="inline-flex items-center gap-1 font-semibold text-[#C13515]">
            <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>CHƯA CẤP · Cấp 0</span>
          </span>
        )}
      </div>

      <div className="space-y-1">
        <label htmlFor="clearance-option-select" className="font-medium text-[#222222]">
          Cấp thẩm quyền mới
        </label>
        <select
          id="clearance-option-select"
          value={selectedOptionId}
          onChange={(e) => setSelectedOptionId(e.target.value)}
          className="w-full min-h-11 sm:h-10 rounded-full border border-[#dddddd] bg-[#ffffff] px-4 py-2 text-xs text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 cursor-pointer"
        >
          <option value="">Chưa cấp / Thu hồi thẩm quyền (Cấp 0)</option>
          {clearanceOptions.map((opt) => (
            <option key={opt.id} value={opt.id}>
              {opt.name} · Cấp {opt.rank}
            </option>
          ))}
        </select>
        <p className="text-[11px] text-[#717171] leading-relaxed pt-0.5">
          Người dùng chỉ có thể tải lên, đọc hoặc được cấp quyền đối với tài liệu có mức độ mật thấp
          hơn hoặc bằng cấp thẩm quyền hiện tại.
        </p>
      </div>

      {isDowngrade && (
        <div className="rounded-[18px] border border-[#E07912]/40 bg-[#f7f7f7] p-3 flex items-start gap-2 text-[#222222]">
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912] mt-0.5"
            aria-hidden="true"
          />
          <div className="space-y-0.5 leading-relaxed">
            <div className="font-semibold text-[#C13515]">
              Cảnh báo hạ cấp thẩm quyền (Cấp {currentRank} → Cấp {nextRank})
            </div>
            <p className="text-[#717171]">
              Mọi quyền truy cập trực tiếp và phiên đọc tài liệu đang mở có mức độ mật cao hơn{' '}
              <strong className="text-[#222222]">Cấp {nextRank}</strong> sẽ bị hệ thống tự động thu
              hồi ngay lập tức.
            </p>
          </div>
        </div>
      )}

      {selectedOption && !isDowngrade && (
        <div className="rounded-[18px] border border-[#008A05]/25 bg-[#008A05]/5 p-3 flex items-center gap-2 text-[#008A05] font-medium">
          <ShieldCheck size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
          <span>
            Cho phép thao tác tài liệu đến mức <strong>{selectedOption.name}</strong> (tối đa Cấp{' '}
            {selectedOption.rank}).
          </span>
        </div>
      )}

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
          variant="primary"
          size="sm"
          text="Lưu thẩm quyền"
          icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
          isLoading={isSubmitting}
          disabled={isSubmitting}
        />
      </DialogFooter>
    </form>
  );
}
