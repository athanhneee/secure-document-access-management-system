'use client';

import { useState, type FormEvent } from 'react';
import { Check, Settings } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { DetectionRuleItem } from '../types';

interface EditDetectionRuleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule: DetectionRuleItem | null;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Cấu Hình Tham Số Cửa Sổ Trượt Luật Phát Hiện Bất Thường (`EditDetectionRuleModal`)
 * Mục đích: Kiểm định miền giá trị ngưỡng (`thresholdCount -> threshold: 1..1000`), cửa sổ (`windowMinutes: 1..1440`), hạ nhiệt (`cooldownMinutes: 1..1440`) và trạng thái bật/tắt qua `PATCH /security-detection/rules/:ruleCode`.
 */
export function EditDetectionRuleModal({
  open,
  onOpenChange,
  rule,
  onClearError,
  onSuccess,
  onError,
}: EditDetectionRuleModalProps) {
  const ruleCode = rule?.ruleCode || rule?.code || '';

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <Settings size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Cấu hình luật phát hiện: {ruleCode}</span>
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            {rule?.name || 'Điều chỉnh ngưỡng kích hoạt, cửa sổ quan sát và thời gian hạ nhiệt'}
          </DialogDescription>
        </DialogHeader>

        {open && rule && ruleCode && (
          <EditDetectionRuleForm
            key={ruleCode}
            rule={rule}
            ruleCode={ruleCode}
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

function EditDetectionRuleForm({
  rule,
  ruleCode,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: {
  rule: DetectionRuleItem;
  ruleCode: string;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}) {
  const [thresholdCount, setThresholdCount] = useState(rule.threshold ?? rule.thresholdCount ?? 5);
  const [windowMinutes, setWindowMinutes] = useState(rule.windowMinutes ?? 15);
  const [cooldownMinutes, setCooldownMinutes] = useState(rule.cooldownMinutes ?? 30);
  const [isEnabled, setIsEnabled] = useState(rule.isEnabled !== false);
  const [isSaving, setIsSaving] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const valid =
      Number.isInteger(thresholdCount) &&
      thresholdCount >= 1 &&
      thresholdCount <= 1000 &&
      Number.isInteger(windowMinutes) &&
      windowMinutes >= 1 &&
      windowMinutes <= 1440 &&
      Number.isInteger(cooldownMinutes) &&
      cooldownMinutes >= 1 &&
      cooldownMinutes <= 1440;
    if (!valid) {
      onError(
        'Ngưỡng (1–1000) và cửa sổ / thời gian hạ nhiệt (1–1440 phút) phải là số nguyên hợp lệ.',
      );
      return;
    }

    setIsSaving(true);
    onClearError();
    try {
      await apiClient(`/security-detection/rules/${encodeURIComponent(ruleCode)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          threshold: thresholdCount,
          windowMinutes,
          cooldownMinutes,
          isEnabled,
        }),
      });
      onClose();
      await onSuccess(`Đã cập nhật cấu hình luật phát hiện [${ruleCode}] thành công.`);
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể lưu cấu hình luật phát hiện.');
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3.5 py-2 text-xs">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="space-y-1">
          <label htmlFor="rule-threshold-count" className="font-medium text-[#222222]">
            Ngưỡng sự kiện <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-threshold-count"
            type="number"
            required
            min={1}
            max={1000}
            value={thresholdCount}
            onChange={(e) => setThresholdCount(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="rule-window-minutes" className="font-medium text-[#222222]">
            Cửa sổ (phút) <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-window-minutes"
            type="number"
            required
            min={1}
            max={1440}
            value={windowMinutes}
            onChange={(e) => setWindowMinutes(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="rule-cooldown-minutes" className="font-medium text-[#222222]">
            Hạ nhiệt (phút) <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-cooldown-minutes"
            type="number"
            required
            min={1}
            max={1440}
            value={cooldownMinutes}
            onChange={(e) => setCooldownMinutes(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
      </div>

      <label
        htmlFor="rule-is-enabled"
        aria-label="Kích hoạt thực thi tự động"
        className="flex items-center justify-between gap-3 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 cursor-pointer"
      >
        <span className="block">
          <span className="block font-semibold text-[#222222]">Kích hoạt thực thi tự động</span>
          <span className="block text-[#717171]">
            Bật hoặc tạm ngưng luật này khi chạy chu kỳ quét SOC
          </span>
        </span>
        <input
          id="rule-is-enabled"
          type="checkbox"
          checked={isEnabled}
          onChange={(e) => setIsEnabled(e.target.checked)}
          className="h-4 w-4 rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
        />
      </label>

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Hủy"
          disabled={isSaving}
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text="Lưu cấu hình"
          icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
          isLoading={isSaving}
          disabled={isSaving}
        />
      </DialogFooter>
    </form>
  );
}
