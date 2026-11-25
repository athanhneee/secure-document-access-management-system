'use client';

import { useState, type FormEvent } from 'react';
import { FileCheck } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { formatDetectionRuleLabel } from '@/lib/ui-labels';
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
import { Textarea } from '@/components/ui/textarea';
import type { IncidentDraftPrefill, SecurityAlertItem } from '../types';

interface CreateIncidentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alerts?: SecurityAlertItem[] | undefined;
  prefill?: IncidentDraftPrefill | null | undefined;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Khởi Tạo Hồ Sơ Báo Cáo Sự Cố An Ninh Ở Trạng Thái DRAFT Kèm Liên Kết Cảnh Báo Nguồn (`CreateIncidentModal`)
 * Mục đích: Kiểm định tiêu đề (`>= 5` ký tự khớp Zod #07), tóm tắt (`>= 10` ký tự), gắn `alertId` tùy chọn (#22) và tắt pop-up HTML5 bằng `noValidate` (N15).
 */
export function CreateIncidentModal({
  open,
  onOpenChange,
  alerts = [],
  prefill,
  onClearError,
  onSuccess,
  onError,
}: CreateIncidentModalProps) {
  const formKey = `${open ? 'open' : 'closed'}-${prefill?.alertId ?? 'none'}-${prefill?.title ?? ''}`;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Tạo hồ sơ sự cố an ninh mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Ghi nhận sự cố để phục vụ quy trình điều tra, khắc phục và báo cáo.
          </DialogDescription>
        </DialogHeader>

        {open && (
          <CreateIncidentForm
            key={formKey}
            alerts={alerts}
            prefill={prefill}
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

function CreateIncidentForm({
  alerts,
  prefill,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: {
  alerts: SecurityAlertItem[];
  prefill?: IncidentDraftPrefill | null | undefined;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}) {
  const [selectedAlertId, setSelectedAlertId] = useState(prefill?.alertId ?? '');
  const [incTitle, setIncTitle] = useState(prefill?.title ?? '');
  const [incSummary, setIncSummary] = useState(prefill?.summary ?? '');
  const [isCreatingInc, setIsCreatingInc] = useState(false);

  const trimmedTitle = incTitle.trim();
  const trimmedSummary = incSummary.trim();
  const canSubmitForm = trimmedTitle.length >= 5 && trimmedSummary.length >= 10 && !isCreatingInc;

  async function handleCreateIncident(e: FormEvent) {
    e.preventDefault();
    if (trimmedTitle.length < 5) {
      onError('Tiêu đề sự cố phải có tối thiểu 5 ký tự.');
      return;
    }
    if (trimmedSummary.length < 10) {
      onError('Tóm tắt diễn biến sự cố phải có tối thiểu 10 ký tự.');
      return;
    }

    setIsCreatingInc(true);
    onClearError();
    try {
      await apiClient('/incidents', {
        method: 'POST',
        body: JSON.stringify({
          ...(selectedAlertId ? { alertId: selectedAlertId } : {}),
          title: trimmedTitle,
          summary: trimmedSummary,
        }),
      });

      onClose();
      await onSuccess('Đã tạo hồ sơ sự cố an ninh (trạng thái Bản nháp).');
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo hồ sơ sự cố.');
      } else {
        onError('Đã xảy ra lỗi khi tạo hồ sơ sự cố.');
      }
    } finally {
      setIsCreatingInc(false);
    }
  }

  return (
    <form onSubmit={handleCreateIncident} className="space-y-3.5 py-2 text-xs" noValidate>
      <div className="space-y-1">
        <label htmlFor="inc-alert-id" className="font-medium text-[#222222]">
          Liên kết cảnh báo an ninh nguồn (tùy chọn)
        </label>
        <select
          id="inc-alert-id"
          value={selectedAlertId}
          onChange={(e) => setSelectedAlertId(e.target.value)}
          className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
        >
          <option value="">Không gắn cảnh báo cụ thể</option>
          {alerts.map((a) => (
            <option key={a.id} value={a.id}>
              [{formatDetectionRuleLabel(a.ruleCode)}] {a.title.slice(0, 70)}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-1">
        <label htmlFor="inc-title" className="font-medium text-[#222222]">
          Tiêu đề sự cố (tối thiểu 5 ký tự) <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="inc-title"
          value={incTitle}
          onChange={(e) => setIncTitle(e.target.value)}
          placeholder="Ví dụ: Nghi vấn rò rỉ tài liệu mật phòng Tài chính"
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171] focus-visible:border-[#FF385C]"
        />
        <p className="text-xs text-[#717171]">Tối thiểu 5 ký tự ({trimmedTitle.length}/5)</p>
      </div>

      <div className="space-y-1">
        <label htmlFor="inc-summary" className="font-medium text-[#222222]">
          Tóm tắt diễn biến &amp; đánh giá tác động <span className="text-[#C13515]">*</span>
        </label>
        <Textarea
          id="inc-summary"
          rows={4}
          value={incSummary}
          onChange={(e) => setIncSummary(e.target.value)}
          placeholder="Mô tả sự việc, các bằng chứng sơ bộ và mức độ rủi ro đối với tổ chức…"
          className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171] focus-visible:border-[#FF385C]"
        />
        <p className="text-xs text-[#717171]">Tối thiểu 10 ký tự ({trimmedSummary.length}/10)</p>
      </div>

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Hủy"
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text="Tạo hồ sơ sự cố"
          icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
          isLoading={isCreatingInc}
          disabled={!canSubmitForm}
        />
      </DialogFooter>
    </form>
  );
}
