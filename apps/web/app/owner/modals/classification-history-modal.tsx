'use client';

import { RefreshCw } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import type { ClassificationHistoryItem, DocumentItem } from '../types';

interface ClassificationHistoryModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  history: ClassificationHistoryItem[];
  isLoading: boolean;
}

export function ClassificationHistoryModal({
  open,
  onOpenChange,
  document,
  history,
  isLoading,
}: ClassificationHistoryModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Lịch sử phân loại SCD Type 2: {document?.title}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Truy vết thay đổi mức độ mật và danh mục nghiệp vụ qua các thời kỳ
          </DialogDescription>
        </DialogHeader>

        <div className="py-2 text-xs">
          {isLoading ? (
            <div className="text-center py-6 text-[#717171]">
              <RefreshCw
                size={20}
                strokeWidth={1.75}
                className="animate-spin mx-auto mb-2 text-[#FF385C]"
                aria-hidden="true"
              />
              Đang tải lịch sử phân loại...
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-6 text-[#717171]">
              Không có dữ liệu lịch sử phân loại
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {history.map((ch) => (
                <div
                  key={ch.id}
                  className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ClassificationBadge level={ch.classificationLevelCode} size="sm" />
                      <span className="font-semibold text-[#222222]">
                        {ch.businessCategoryName}
                      </span>
                    </div>
                    <span className="text-[13px] text-[#717171]">
                      {ch.effectiveTo ? (
                        `Hiệu lực đến: ${new Date(ch.effectiveTo).toLocaleDateString('vi-VN')}`
                      ) : (
                        <Badge variant="success" className="text-[13px]">
                          Đang hiệu lực
                        </Badge>
                      )}
                    </span>
                  </div>
                  <div className="text-xs text-[#717171]">
                    <div>Hiệu lực từ: {new Date(ch.effectiveFrom).toLocaleString('vi-VN')}</div>
                    <div>
                      Lý do: <span className="text-[#222222]">{ch.reason || '—'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <DialogFooter>
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Đóng"
            onClick={() => onOpenChange(false)}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
