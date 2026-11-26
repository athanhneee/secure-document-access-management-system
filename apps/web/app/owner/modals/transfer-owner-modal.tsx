'use client';

import { type FormEvent } from 'react';
import { AlertTriangle, ArrowRightLeft, RefreshCw } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { formatUserLookupOptionLabel } from '../grant-helpers';
import type { DocumentItem, UserLookupItem } from '../types';

interface TransferOwnerModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  eligibleUsers: UserLookupItem[];
  isLoadingUsers: boolean;
  newOwnerId: string;
  onNewOwnerIdChange: (value: string) => void;
  reason: string;
  onReasonChange: (value: string) => void;
  isTransferring: boolean;
  onSubmit: (e: FormEvent) => void;
}

/**
 * Thuật toán: Biểu Mẫu Chuyển Giao Chủ Sở Hữu Tài Liệu (`POST /documents/:id/transfer-owner`, BUG-030 / HIGH-16)
 * Mục đích:
 *   - Cho phép chủ sở hữu hiện tại bàn giao quyền quản trị tài liệu sang một người dùng hợp lệ khác (không tự chuyển cho chính mình và loại tài khoản SoD).
 *   - Yêu cầu ghi nhận lý do kiểm toán (`1..500` ký tự), cảnh báo rõ việc thu hồi ngay quyền chủ sở hữu hiện tại và khóa đóng hộp thoại khi đang gửi.
 */
export function TransferOwnerModal({
  open,
  onOpenChange,
  document,
  eligibleUsers,
  isLoadingUsers,
  newOwnerId,
  onNewOwnerIdChange,
  reason,
  onReasonChange,
  isTransferring,
  onSubmit,
}: TransferOwnerModalProps) {
  const trimmedReason = reason.trim();
  const hasSelectedUser = eligibleUsers.some((u) => u.id === newOwnerId);
  const isSubmitDisabled =
    isTransferring ||
    isLoadingUsers ||
    !hasSelectedUser ||
    trimmedReason.length < 1 ||
    trimmedReason.length > 500;

  return (
    <Dialog open={open} onOpenChange={(next) => !isTransferring && onOpenChange(next)}>
      <DialogContent
        showClose={!isTransferring}
        className="max-w-lg max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <ArrowRightLeft
              size={20}
              strokeWidth={1.75}
              className="text-[#FF385C]"
              aria-hidden="true"
            />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Chuyển chủ sở hữu tài liệu
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Bàn giao toàn bộ quyền quản lý, phân loại và cấp quyền truy cập của tài liệu{' '}
            <strong className="text-[#222222]">{document?.title}</strong> sang chủ sở hữu mới.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} noValidate className="space-y-3.5 py-2 text-xs">
          <Alert variant="warning" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2 leading-relaxed">
              Ngay sau khi xác nhận, tài liệu sẽ chuyển sang danh sách quản lý của chủ sở hữu mới và
              quyền chủ sở hữu tự động của bạn đối với tài liệu này sẽ bị thu hồi.
            </AlertDescription>
          </Alert>

          <div className="space-y-1">
            <label htmlFor="transfer-new-owner" className="font-medium text-[#222222]">
              Chủ sở hữu mới <span className="text-[#C13515]">*</span>
            </label>
            {isLoadingUsers && eligibleUsers.length === 0 ? (
              <div className="flex items-center gap-2 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-3.5 py-2.5 text-[#717171]">
                <RefreshCw
                  size={16}
                  strokeWidth={1.75}
                  className="animate-spin text-[#FF385C]"
                  aria-hidden="true"
                />
                <span>Đang tải danh sách người dùng hợp lệ…</span>
              </div>
            ) : (
              <Select
                id="transfer-new-owner"
                disabled={isTransferring || eligibleUsers.length === 0}
                value={hasSelectedUser ? newOwnerId : ''}
                onChange={(e) => onNewOwnerIdChange(e.target.value)}
              >
                {eligibleUsers.length === 0 ? (
                  <option value="">Không có người dùng hợp lệ để nhận bàn giao</option>
                ) : (
                  eligibleUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {formatUserLookupOptionLabel(u)}
                    </option>
                  ))
                )}
              </Select>
            )}
            <p className="text-[11px] text-[#717171]">
              Chủ sở hữu mới phải có quyền quản trị tài liệu (DOCUMENT:MANAGE), cấp thẩm quyền đủ
              cho mức độ mật và không thuộc nhóm vai trò xung đột lợi ích (SoD).
            </p>
          </div>

          <div className="space-y-1">
            <label htmlFor="transfer-owner-reason" className="font-medium text-[#222222]">
              Lý do bàn giao quyền sở hữu <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="transfer-owner-reason"
              rows={3}
              maxLength={500}
              disabled={isTransferring}
              value={reason}
              onChange={(e) => onReasonChange(e.target.value)}
              placeholder="Ví dụ: Bàn giao phụ trách dự án tài liệu mật sau khi điều chuyển công tác…"
              className="text-xs rounded-[18px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
            />
            <p className="text-[11px] text-[#717171]">{trimmedReason.length}/500 ký tự</p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isTransferring}
              onClick={() => onOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text={isTransferring ? 'Đang bàn giao…' : 'Xác nhận chuyển giao'}
              icon={<ArrowRightLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isTransferring}
              disabled={isSubmitDisabled}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
