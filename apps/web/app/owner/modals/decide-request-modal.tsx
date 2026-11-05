'use client';

import { Eye, Download } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import type { AccessRequestItem } from '../types';

interface DecideRequestModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  request: AccessRequestItem | null;
  grantAction: 'VIEW' | 'DOWNLOAD';
  onActionChange: (action: 'VIEW' | 'DOWNLOAD') => void;
  grantValidDays: number;
  onValidDaysChange: (days: number) => void;
  isApproving: boolean;
  onConfirmApprove: () => void;
}

export function DecideRequestModal({
  open,
  onOpenChange,
  request,
  grantAction,
  onActionChange,
  grantValidDays,
  onValidDaysChange,
  isApproving,
  onConfirmApprove,
}: DecideRequestModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Cấp giấy phép truy cập có thời hạn
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Xác định quyền (VIEW hoặc DOWNLOAD) và giới hạn thời gian hiệu lực
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Người nhận quyền: <strong className="text-[#222222]">{request?.requestorName}</strong>
            </div>
            <div>
              Tài liệu: <span className="text-[#222222]">{request?.documentTitle}</span>
            </div>
            {request?.requestedFrom && request?.requestedUntil && (
              <div className="text-[#008489] font-medium pt-1 border-t border-[#ebebeb]">
                Thời gian yêu cầu: {new Date(request.requestedFrom).toLocaleDateString('vi-VN')} đến{' '}
                {new Date(request.requestedUntil).toLocaleDateString('vi-VN')}
              </div>
            )}
          </div>

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">Phạm vi quyền cấp:</legend>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                aria-pressed={grantAction === 'VIEW'}
                onClick={() => onActionChange('VIEW')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold cursor-pointer ${
                  grantAction === 'VIEW'
                    ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd]'
                }`}
              >
                <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Chỉ xem (VIEW)</span>
              </button>
              <button
                type="button"
                aria-pressed={grantAction === 'DOWNLOAD'}
                onClick={() => onActionChange('DOWNLOAD')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold cursor-pointer ${
                  grantAction === 'DOWNLOAD'
                    ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                    : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd]'
                }`}
              >
                <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xem & Tải (DOWNLOAD)</span>
              </button>
            </div>
          </fieldset>

          <div className="space-y-1">
            <label htmlFor="grant-duration" className="font-medium text-[#222222]">
              Thời hạn hiệu lực (Ngày):
            </label>
            <select
              id="grant-duration"
              value={grantValidDays}
              onChange={(e) => onValidDaysChange(Number(e.target.value))}
              className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              <option value={1}>1 ngày (24 giờ khẩn cấp)</option>
              <option value={3}>3 ngày</option>
              <option value={7}>7 ngày (1 tuần làm việc)</option>
              <option value={14}>14 ngày</option>
              <option value={30}>30 ngày</option>
            </select>
          </div>
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
            type="button"
            variant="primary"
            size="sm"
            text="Xác nhận cấp quyền"
            disabled={isApproving}
            isLoading={isApproving}
            onClick={onConfirmApprove}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
