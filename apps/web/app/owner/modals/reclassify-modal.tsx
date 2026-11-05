'use client';

import type { FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
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
}

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
}: ReclassifyModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={20}
              strokeWidth={1.75}
              className="text-[#FF385C]"
              aria-hidden="true"
            />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Điều chỉnh phân loại mật (Reclassify)
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Lịch sử phân loại SCD Type 2 sẽ được ghi nhận phục vụ kiểm toán
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-3.5 py-2 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
            <div>
              Tài liệu: <strong>{document?.title}</strong>
            </div>
            <div>
              Mức mật hiện tại:{' '}
              <ClassificationBadge
                level={document?.classificationCode ?? 'CONFIDENTIAL'}
                size="sm"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="reclass-level" className="font-medium text-[#222222]">
              Mức độ mật mới <span className="text-[#C13515]">*</span>
            </label>
            <select
              id="reclass-level"
              value={reclassLevelId}
              onChange={(e) => onLevelChange(Number(e.target.value))}
              className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              {classificationLevels.map((lvl) => (
                <option key={lvl.id} value={lvl.id}>
                  {lvl.name} ({lvl.code}) · Rank {lvl.rank}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label htmlFor="reclass-cat" className="font-medium text-[#222222]">
              Danh mục nghiệp vụ <span className="text-[#C13515]">*</span>
            </label>
            <select
              id="reclass-cat"
              value={reclassCategoryId}
              onChange={(e) => onCategoryChange(Number(e.target.value))}
              className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              {businessCategories.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.code})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label htmlFor="reclass-reason" className="font-medium text-[#222222]">
              Lý do điều chỉnh (Kiểm toán bắt buộc) <span className="text-[#C13515]">*</span>
            </label>
            <Textarea
              id="reclass-reason"
              required
              rows={3}
              value={reclassReason}
              onChange={(e) => onReasonChange(e.target.value)}
              placeholder="Ví dụ: Hạ cấp độ mật sau khi báo cáo được công bố chính thức..."
              className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
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
              type="submit"
              variant="primary"
              size="sm"
              text="Lưu thay đổi"
              disabled={isReclassifying}
              isLoading={isReclassifying}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
