'use client';

import { useState } from 'react';
import { Check } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
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
import type { SecurityAlertItem } from '../types';

interface AlertDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: SecurityAlertItem | null;
  onClearError: () => void;
  // CONFLICT-RESOLVED: Bổ sung `| undefined` tường minh để tương thích `exactOptionalPropertyTypes: true` khi truyền callback cập nhật lạc quan xuống AlertDetailForm.
  onOptimisticStatusChange?:
    ((alertId: string, nextStatus: SecurityAlertItem['status']) => () => void) | undefined;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AlertDetailModal({
  open,
  onOpenChange,
  alert,
  onClearError,
  onOptimisticStatusChange,
  onSuccess,
  onError,
}: AlertDetailModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chi tiết cảnh báo an ninh #{alert?.id}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Cập nhật trạng thái điều tra theo máy trạng thái nghiêm ngặt
          </DialogDescription>
        </DialogHeader>

        {open && alert && (
          <AlertDetailForm
            key={alert.id}
            alert={alert}
            onClose={() => onOpenChange(false)}
            onClearError={onClearError}
            onOptimisticStatusChange={onOptimisticStatusChange}
            onSuccess={onSuccess}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

/**
 * Thuật toán: Máy Trạng Thái Chuyển Tiếp Cảnh Báo An Ninh & Bổ Sung Ghi Chú Điều Tra Độc Lập (`VALID_TRANSITIONS`)
 * Mục đích: Khóa danh sách trạng thái đích hợp lệ theo trạng thái hiện tại, bỏ qua lệnh tự chuyển tiếp (`PATCH /status`) khi chỉ ghi chú điều tra và cho phép đính kèm ghi chú ngay cả ở trạng thái kết thúc.
 * Cơ chế hoạt động:
 *   - Sinh tập trạng thái cho phép `[alert.status, ...VALID_TRANSITIONS[alert.status]]`; vô hiệu hóa thẻ `<select>` khi cảnh báo đã đóng (`RESOLVED` / `FALSE_POSITIVE`).
 *   - Chỉ phát truy vấn `PATCH /security-alerts/:id/status` khi `newStatus !== alert.status`; nếu `newStatus === alert.status` và có `investigationNote`, chuyển thẳng tới `POST /security-alerts/:id/notes`.
 */
// CONFLICT-RESOLVED: Đồng bộ tập trạng thái chuyển tiếp với AlertStatusSchema (@sda/contracts) và enum CSDL alert_status để không gửi ESCALATED gây lỗi 400, vẫn hỗ trợ ESCALATED -> RESOLVED nếu nhận từ API.
const VALID_TRANSITIONS: Record<SecurityAlertItem['status'], SecurityAlertItem['status'][]> = {
  OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
  INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE'],
  ESCALATED: ['RESOLVED'],
  RESOLVED: [],
  FALSE_POSITIVE: [],
};

const STATUS_LABELS: Record<SecurityAlertItem['status'], string> = {
  OPEN: 'OPEN (Đang mở)',
  INVESTIGATING: 'INVESTIGATING (Đang điều tra)',
  ESCALATED: 'ESCALATED (Đã leo thang)',
  RESOLVED: 'RESOLVED (Đã xử lý)',
  FALSE_POSITIVE: 'FALSE_POSITIVE (Báo động giả)',
};

interface AlertDetailFormProps {
  alert: SecurityAlertItem;
  onClose: () => void;
  onClearError: () => void;
  // CONFLICT-RESOLVED: Bổ sung `| undefined` tường minh để tương thích `exactOptionalPropertyTypes: true` khi truyền callback cập nhật lạc quan xuống AlertDetailForm.
  onOptimisticStatusChange?:
    ((alertId: string, nextStatus: SecurityAlertItem['status']) => () => void) | undefined;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function AlertDetailForm({
  alert,
  onClose,
  onClearError,
  onOptimisticStatusChange,
  onSuccess,
  onError,
}: AlertDetailFormProps) {
  const allowedStatuses = Array.from(
    new Set<SecurityAlertItem['status']>([
      alert.status,
      ...(VALID_TRANSITIONS[alert.status] ?? []),
    ]),
  );
  const isTerminalStatus = allowedStatuses.length <= 1;

  const [newStatus, setNewStatus] = useState<SecurityAlertItem['status']>(alert.status);
  const [resolutionNote, setResolutionNote] = useState('');
  const [investigationNote, setInvestigationNote] = useState('');
  const [isUpdatingAlert, setIsUpdatingAlert] = useState(false);

  const statusChanged = newStatus !== alert.status;
  const requiresResolutionNote =
    statusChanged && (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE');

  async function handleUpdateAlertStatus() {
    const trimmedResNote = resolutionNote.trim();
    const trimmedInvNote = investigationNote.trim();

    if (!statusChanged && !trimmedInvNote) {
      onError('Vui lòng chọn trạng thái chuyển tiếp mới hoặc nhập ghi chú điều tra nội bộ.');
      return;
    }

    if (requiresResolutionNote && trimmedResNote.length < 5) {
      onError(
        'Cần ghi rõ ghi chú kết luận xử lý (ít nhất 5 ký tự) khi đóng hoặc đánh dấu false-positive.',
      );
      return;
    }

    if (trimmedInvNote && trimmedInvNote.length < 5) {
      onError('Ghi chú điều tra nội bộ cần tối thiểu 5 ký tự.');
      return;
    }

    setIsUpdatingAlert(true);
    onClearError();
    const rollback = statusChanged ? onOptimisticStatusChange?.(alert.id, newStatus) : undefined;
    onClose();

    try {
      if (statusChanged) {
        await apiClient(`/security-alerts/${alert.id}/status`, {
          method: 'PATCH',
          body: JSON.stringify({
            status: newStatus,
            resolutionNote: trimmedResNote || undefined,
          }),
        });
      }

      if (trimmedInvNote) {
        await apiClient(`/security-alerts/${alert.id}/notes`, {
          method: 'POST',
          body: JSON.stringify({ note: trimmedInvNote }),
        });
      }

      await onSuccess(
        statusChanged
          ? `Đã cập nhật trạng thái cảnh báo thành ${newStatus}.`
          : 'Đã lưu ghi chú điều tra nội bộ cho cảnh báo.',
      );
    } catch (err) {
      rollback?.();
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể cập nhật cảnh báo.');
      } else {
        onError('Đã xảy ra lỗi khi cập nhật cảnh báo.');
      }
    } finally {
      setIsUpdatingAlert(false);
    }
  }

  return (
    <>
      <div className="space-y-3.5 py-2 text-xs">
        <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
          <div className="flex justify-between">
            <span className="text-[#717171]">Quy tắc:</span>
            <span className="font-bold text-[#222222]">{alert.ruleCode}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#717171]">Đối tượng:</span>
            <span className="font-medium text-[#222222]">{alert.detectedUserName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#717171]">Địa chỉ IP:</span>
            <span className="font-bold text-[#222222]">{alert.ipAddress}</span>
          </div>
        </div>

        <div className="space-y-1">
          <label htmlFor="alert-status-select" className="font-medium text-[#222222]">
            Chuyển đổi trạng thái:
          </label>
          <select
            id="alert-status-select"
            value={newStatus}
            disabled={isTerminalStatus || isUpdatingAlert}
            onChange={(e) => setNewStatus(e.target.value as SecurityAlertItem['status'])}
            className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {allowedStatuses.map((statusOption) => (
              <option key={statusOption} value={statusOption}>
                {STATUS_LABELS[statusOption]}
              </option>
            ))}
          </select>
          {isTerminalStatus && (
            <p className="text-xs text-[#717171]">
              Cảnh báo đã ở trạng thái kết thúc; bạn vẫn có thể lưu thêm ghi chú điều tra bên dưới.
            </p>
          )}
        </div>

        {requiresResolutionNote && (
          <div className="space-y-1">
            <label htmlFor="res-note" className="font-medium text-[#222222]">
              Ghi chú kết luận (Bắt buộc tối thiểu 5 ký tự){' '}
              <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="res-note"
              rows={2}
              value={resolutionNote}
              onChange={(e) => setResolutionNote(e.target.value)}
              placeholder="Nêu rõ kết quả xác minh hoặc nguyên nhân báo động giả..."
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
            />
          </div>
        )}

        <div className="space-y-1">
          <label htmlFor="inv-note" className="font-medium text-[#222222]">
            Thêm ghi chú điều tra nội bộ:
          </label>
          <Textarea
            id="inv-note"
            rows={2}
            value={investigationNote}
            onChange={(e) => setInvestigationNote(e.target.value)}
            placeholder="Ghi nhận các bước rà soát log, trao đổi với người dùng..."
            className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>
      </div>

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Đóng"
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="button"
          variant="primary"
          size="sm"
          text="Cập nhật cảnh báo"
          icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
          isLoading={isUpdatingAlert}
          disabled={isUpdatingAlert}
          onClick={() => void handleUpdateAlertStatus()}
        />
      </DialogFooter>
    </>
  );
}
