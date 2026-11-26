'use client';

import type { FormEvent } from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { isClassificationAllowedForClearance, rankFromCode } from '../helpers';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DocumentItem,
} from '../types';

interface ReclassifyModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  reclassLevelId: number;
  onLevelChange: (id: number) => void;
  reclassCategoryId: number;
  onCategoryChange: (id: number) => void;
  reclassReason: string;
  onReasonChange: (reason: string) => void;
  isReclassifying: boolean;
  onSubmit: (e: FormEvent) => void;
  classificationLevels: ClassificationLevelLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  userClearanceRank?: number | null | undefined;
}

/**
 * Thuật toán: Hộp Thoại Điều Chỉnh Mức Độ Mật Có Ràng Buộc Trần Bell-LaPadula & Cảnh Báo Thu Hồi Dây Chuyền Phẳng (`ReclassifyModal`, BUG-100, BUG-102)
 * Mục đích:
 *   - Khóa các `<option>` có `rank > userClearanceRank` kèm hậu tố `(Vượt cấp thẩm quyền)`.
 *   - Hiển thị cảnh báo phẳng không đóng hộp viền màu khi nâng bậc mật hoặc siết chính sách tải về.
 *   - Áp `maxLength={500}`, `noValidate` và chặn đóng modal khi đang gửi API.
 */
export function ReclassifyModal({
  open,
  onOpenChange,
  document,
  reclassLevelId,
  onLevelChange,
  reclassCategoryId,
  onCategoryChange,
  reclassReason,
  onReasonChange,
  isReclassifying,
  onSubmit,
  classificationLevels,
  businessCategories,
  userClearanceRank,
}: ReclassifyModalProps) {
  const currentDocRank = document?.classificationRank ?? rankFromCode(document?.classificationCode);
  const selectedLevel = classificationLevels.find(
    (lvl) => Number(lvl.id) === Number(reclassLevelId),
  );
  const selectedExceedsClearance =
    selectedLevel !== undefined &&
    !isClassificationAllowedForClearance(selectedLevel.rank, userClearanceRank);
  const isRankIncreased = selectedLevel !== undefined && selectedLevel.rank > currentDocRank;
  const isDownloadTightened =
    Boolean(document?.allowDownload) && selectedLevel !== undefined && !selectedLevel.allowDownload;
  const showCascadeWarning = isRankIncreased || isDownloadTightened;

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isReclassifying) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isReclassifying}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={20}
              strokeWidth={1.75}
              className="text-[#FF385C]"
              aria-hidden="true"
            />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Điều chỉnh mức độ mật
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Mọi thay đổi về mức độ mật sẽ được lưu vào lịch sử phân loại phục vụ kiểm toán.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} noValidate className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Tài liệu: <strong>{document?.title}</strong>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span>Mức độ mật hiện tại:</span>
              <ClassificationBadge
                level={document?.classificationCode ?? 'CONFIDENTIAL'}
                showRank
                size="sm"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="reclass-level" className="font-medium text-[#222222]">
              Mức độ mật mới <span className="text-[#C13515]">*</span>
            </label>
            <Select
              id="reclass-level"
              disabled={isReclassifying}
              value={String(reclassLevelId)}
              onChange={(e) => onLevelChange(Number(e.target.value))}
            >
              {classificationLevels.map((lvl) => {
                const exceedsClearance = !isClassificationAllowedForClearance(
                  lvl.rank,
                  userClearanceRank,
                );
                return (
                  <option key={lvl.id} value={String(lvl.id)} disabled={exceedsClearance}>
                    {lvl.name} · Cấp {lvl.rank}
                    {exceedsClearance ? ' (Vượt cấp thẩm quyền)' : ''}
                  </option>
                );
              })}
            </Select>
          </div>

          {showCascadeWarning && selectedLevel && (
            <output className="flex items-start gap-2 text-xs text-[#222222]">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#E07912] mt-0.5"
                aria-hidden="true"
              />
              <span className="leading-relaxed text-[#717171]">
                <strong className="text-[#222222]">Cảnh báo thu hồi dây chuyền:</strong>{' '}
                {isRankIncreased
                  ? `Nâng mức độ mật lên ${selectedLevel.name} (Cấp ${selectedLevel.rank}) sẽ tự động thu hồi/tạm ngưng các quyền truy cập của người dùng có thẩm quyền thấp hơn Cấp ${selectedLevel.rank} và ngắt ngay các phiên xem đang mở.`
                  : `Chuyển sang mức ${selectedLevel.name} sẽ thu hồi quyền tải về trên các giấy phép hiện hành và ngắt các phiên đang mở không còn thỏa chính sách.`}
              </span>
            </output>
          )}

          <div className="space-y-1">
            <label htmlFor="reclass-cat" className="font-medium text-[#222222]">
              Danh mục nghiệp vụ <span className="text-[#C13515]">*</span>
            </label>
            <Select
              id="reclass-cat"
              disabled={isReclassifying}
              value={String(reclassCategoryId)}
              onChange={(e) => onCategoryChange(Number(e.target.value))}
            >
              {businessCategories.map((c) => (
                <option key={c.id} value={String(c.id)}>
                  {c.name}
                </option>
              ))}
            </Select>
          </div>

          <div className="space-y-1">
            <label htmlFor="reclass-reason" className="font-medium text-[#222222]">
              Lý do điều chỉnh (bắt buộc lưu nhật ký) <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="reclass-reason"
              required
              disabled={isReclassifying}
              maxLength={500}
              rows={3}
              value={reclassReason}
              onChange={(e) => onReasonChange(e.target.value)}
              placeholder="Ví dụ: Hạ mức độ mật sau khi báo cáo được công bố chính thức…"
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
            <p className="text-[11px] text-[#717171] tabular-nums">
              {reclassReason.trim().length} / 500 ký tự
            </p>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isReclassifying}
              onClick={() => handleDialogOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Lưu thay đổi"
              disabled={isReclassifying || !reclassReason.trim() || selectedExceedsClearance}
              isLoading={isReclassifying}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
