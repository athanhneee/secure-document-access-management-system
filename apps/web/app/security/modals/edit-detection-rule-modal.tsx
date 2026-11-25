'use client';

import { useState, type FormEvent } from 'react';
import { Check, Lock, Settings } from 'lucide-react';
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
 * Thuật toán: Cấu Hình Tham Số Cửa Sổ Trượt, Mức Nghiêm Trọng & Tham Số Giờ Làm Việc Luật Phát Hiện SOC (`EditDetectionRuleModal`)
 * Mục đích: Kiểm định miền giá trị ngưỡng (`1..1000`), cửa sổ/giãn cách (`1..1440`), chỉnh `startHourUtc`/`endHourUtc` & `minClassificationRank` cho `OFF_HOURS_ACCESS` (#26), khóa bật bắt buộc cho `AUDIT_INTEGRITY_COMPROMISED` (N04) và dùng `noValidate` (N15).
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
      <DialogContent className="max-w-md max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <Settings size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Cấu hình quy tắc phát hiện: {ruleCode}</span>
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            {rule?.name ||
              'Điều chỉnh ngưỡng kích hoạt, khung thời gian theo dõi và thời gian giãn cách cảnh báo.'}
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
  const isMandatoryRule = ruleCode === 'AUDIT_INTEGRITY_COMPROMISED';
  const isOffHoursRule = ruleCode === 'OFF_HOURS_ACCESS';
  const initialStartUtc = Number(rule.parameters?.['startHourUtc'] ?? 0);
  const initialEndUtc = Number(rule.parameters?.['endHourUtc'] ?? 11);
  const initialMinRank = Number(rule.parameters?.['minClassificationRank'] ?? 2);

  const [severity, setSeverity] = useState(rule.severity || 'HIGH');
  const [thresholdCount, setThresholdCount] = useState(rule.threshold ?? rule.thresholdCount ?? 5);
  const [windowMinutes, setWindowMinutes] = useState(rule.windowMinutes ?? 15);
  const [cooldownMinutes, setCooldownMinutes] = useState(rule.cooldownMinutes ?? 30);
  const [startHourVn, setStartHourVn] = useState((initialStartUtc + 7) % 24);
  const [endHourVn, setEndHourVn] = useState((initialEndUtc + 7) % 24);
  const [minClassificationRank, setMinClassificationRank] = useState(
    Number.isFinite(initialMinRank) ? initialMinRank : 2,
  );
  const [isEnabled, setIsEnabled] = useState(isMandatoryRule ? true : rule.isEnabled !== false);
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
        'Ngưỡng (1–1000) và khung theo dõi / giãn cách cảnh báo (1–1440 phút) phải là số nguyên hợp lệ.',
      );
      return;
    }

    if (
      isOffHoursRule &&
      (!Number.isInteger(startHourVn) ||
        startHourVn < 0 ||
        startHourVn > 23 ||
        !Number.isInteger(endHourVn) ||
        endHourVn < 0 ||
        endHourVn > 23)
    ) {
      onError('Giờ bắt đầu và giờ kết thúc hành chính (giờ Việt Nam) phải nằm trong khoảng 0–23.');
      return;
    }

    setIsSaving(true);
    onClearError();
    try {
      const nextParameters = isOffHoursRule
        ? {
            ...(rule.parameters ?? {}),
            startHourUtc: (startHourVn + 24 - 7) % 24,
            endHourUtc: (endHourVn + 24 - 7) % 24,
            timezoneOffsetMinutes: 420,
            minClassificationRank,
          }
        : undefined;

      await apiClient(`/security-detection/rules/${encodeURIComponent(ruleCode)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          severity,
          threshold: thresholdCount,
          windowMinutes,
          cooldownMinutes,
          isEnabled: isMandatoryRule ? true : isEnabled,
          ...(nextParameters ? { parameters: nextParameters } : {}),
        }),
      });
      onClose();
      await onSuccess(`Đã cập nhật cấu hình quy tắc phát hiện [${ruleCode}] thành công.`);
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể lưu cấu hình quy tắc phát hiện.');
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3.5 py-2 text-xs" noValidate>
      <div className="space-y-1">
        <label htmlFor="rule-severity" className="font-medium text-[#222222]">
          Mức độ nghiêm trọng <span className="text-[#C13515]">*</span>
        </label>
        <select
          id="rule-severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] cursor-pointer"
        >
          <option value="LOW">Thấp</option>
          <option value="MEDIUM">Trung bình</option>
          <option value="HIGH">Cao</option>
          <option value="CRITICAL">Nghiêm trọng</option>
        </select>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="space-y-1">
          <label htmlFor="rule-threshold-count" className="font-medium text-[#222222]">
            Ngưỡng sự kiện <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-threshold-count"
            type="number"
            min={1}
            max={1000}
            value={thresholdCount}
            onChange={(e) => setThresholdCount(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="rule-window-minutes" className="font-medium text-[#222222]">
            Khung theo dõi (phút) <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-window-minutes"
            type="number"
            min={1}
            max={1440}
            value={windowMinutes}
            onChange={(e) => setWindowMinutes(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="rule-cooldown-minutes" className="font-medium text-[#222222]">
            Giãn cách (phút) <span className="text-[#C13515]">*</span>
          </label>
          <Input
            id="rule-cooldown-minutes"
            type="number"
            min={1}
            max={1440}
            value={cooldownMinutes}
            onChange={(e) => setCooldownMinutes(Number(e.target.value))}
            className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
          />
        </div>
      </div>

      {isOffHoursRule && (
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-2.5">
          <div className="font-semibold text-[#222222]">
            Khung giờ hành chính cho phép (Múi giờ Việt Nam UTC+7)
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <div className="space-y-1">
              <label htmlFor="rule-start-vn" className="font-medium text-[#222222]">
                Từ giờ (0–23)
              </label>
              <Input
                id="rule-start-vn"
                type="number"
                min={0}
                max={23}
                value={startHourVn}
                onChange={(e) => setStartHourVn(Number(e.target.value))}
                className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="rule-end-vn" className="font-medium text-[#222222]">
                Đến giờ (0–23)
              </label>
              <Input
                id="rule-end-vn"
                type="number"
                min={0}
                max={23}
                value={endHourVn}
                onChange={(e) => setEndHourVn(Number(e.target.value))}
                className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="rule-min-rank" className="font-medium text-[#222222]">
                Độ mật tối thiểu
              </label>
              <select
                id="rule-min-rank"
                value={minClassificationRank}
                onChange={(e) => setMinClassificationRank(Number(e.target.value))}
                className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222]"
              >
                <option value={1}>Từ Nội bộ trở lên</option>
                <option value={2}>Từ Mật trở lên</option>
                <option value={3}>Từ Tối mật trở lên</option>
                <option value={4}>Chỉ Tuyệt mật</option>
              </select>
            </div>
          </div>
        </div>
      )}

      <label
        htmlFor="rule-is-enabled"
        aria-label="Bật kiểm tra tự động"
        className={`flex items-center justify-between gap-3 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 ${isMandatoryRule ? 'opacity-80 cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <span className="block">
          <span className="flex items-center gap-1.5 font-semibold text-[#222222]">
            {isMandatoryRule && (
              <Lock size={16} strokeWidth={1.75} className="text-[#C13515]" aria-hidden="true" />
            )}
            <span>{isMandatoryRule ? 'Quy tắc bắt buộc hệ thống' : 'Bật kiểm tra tự động'}</span>
          </span>
          <span className="block text-[#717171]">
            {isMandatoryRule
              ? 'Kiểm tra toàn vẹn chuỗi băm kiểm toán không thể tạm dừng theo chính sách tuân thủ.'
              : 'Bật hoặc tạm dừng quy tắc này trong chu kỳ quét an ninh.'}
          </span>
        </span>
        <input
          id="rule-is-enabled"
          type="checkbox"
          disabled={isMandatoryRule}
          checked={isEnabled}
          onChange={(e) => setIsEnabled(e.target.checked)}
          className="h-4 w-4 rounded border-[#dddddd] accent-[#FF385C]"
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
