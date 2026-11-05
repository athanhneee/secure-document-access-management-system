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
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AlertDetailModal({
  open,
  onOpenChange,
  alert,
  onClearError,
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
            onSuccess={onSuccess}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

interface AlertDetailFormProps {
  alert: SecurityAlertItem;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function AlertDetailForm({
  alert,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: AlertDetailFormProps) {
  const [newStatus, setNewStatus] = useState<SecurityAlertItem['status']>(
    alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
  );
  const [resolutionNote, setResolutionNote] = useState('');
  const [investigationNote, setInvestigationNote] = useState('');
  const [isUpdatingAlert, setIsUpdatingAlert] = useState(false);

  async function handleUpdateAlertStatus() {
    if (
      (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') &&
      resolutionNote.trim().length < 5
    ) {
      onError(
        'Cần ghi rõ ghi chú kết luận xử lý (ít nhất 5 ký tự) khi đóng hoặc đánh dấu false-positive.',
      );
      return;
    }

    setIsUpdatingAlert(true);
    onClearError();

    try {
      await apiClient(`/security-alerts/${alert.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: newStatus,
          resolutionNote: resolutionNote.trim() || undefined,
        }),
      });

      if (investigationNote.trim()) {
        await apiClient(`/security-alerts/${alert.id}/notes`, {
          method: 'POST',
          body: JSON.stringify({ note: investigationNote.trim() }),
        });
      }

      onClose();
      await onSuccess(`Đã cập nhật trạng thái cảnh báo thành ${newStatus}.`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể cập nhật trạng thái cảnh báo.');
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
            onChange={(e) =>
              setNewStatus(
                e.target.value as 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE',
              )
            }
            className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            <option value="OPEN">OPEN (Đang mở)</option>
            <option value="INVESTIGATING">INVESTIGATING (Đang điều tra)</option>
            <option value="RESOLVED">RESOLVED (Đã xử lý)</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE (Báo động giả)</option>
          </select>
        </div>

        {(newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') && (
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
