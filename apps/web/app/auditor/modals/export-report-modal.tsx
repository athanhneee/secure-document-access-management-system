'use client';

import { useState, type FormEvent } from 'react';
import { Download, FileJson, FileSpreadsheet, FileText, Shield } from 'lucide-react';
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
import { normalizeExportJob } from '../helpers';
import type { ExportFormat, ExportJobItem } from '../types';

interface ExportReportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onClearError: () => void;
  onJobCreated: (job: ExportJobItem, message: string) => void;
  onError: (errorMessage: string) => void;
}

const FORMAT_OPTIONS: Array<{
  value: ExportFormat;
  label: string;
  Icon: typeof FileSpreadsheet;
}> = [
  { value: 'CSV', label: 'CSV', Icon: FileSpreadsheet },
  { value: 'EXCEL', label: 'Excel (.xlsx)', Icon: FileSpreadsheet },
  { value: 'JSON', label: 'JSON', Icon: FileJson },
  { value: 'PDF', label: 'PDF', Icon: FileText },
];

/**
 * Thuật toán: Khởi Tạo Tác Vụ Xuất Báo Cáo Kiểm Toán Bất Đồng Bộ (`ExportReportModal`)
 * Mục đích: Gửi `POST /reports/export` theo định dạng được chọn (`CSV`, `EXCEL`, `JSON`, `PDF`), chờ phản hồi thành công mới đóng `<dialog>` và đưa tác vụ vào hàng đợi tải xuống.
 */
export function ExportReportModal({
  open,
  onOpenChange,
  onClearError,
  onJobCreated,
  onError,
}: ExportReportModalProps) {
  const [exportFormat, setExportFormat] = useState<ExportFormat>('CSV');
  const [isExporting, setIsExporting] = useState(false);

  async function handleTriggerExport(e: FormEvent) {
    e.preventDefault();
    setIsExporting(true);
    onClearError();

    try {
      const newJob = await apiClient<ExportJobItem>('/reports/export', {
        method: 'POST',
        body: JSON.stringify({
          exportType: 'AUDIT_LOGS',
          format: exportFormat,
        }),
      });

      const normalized = normalizeExportJob(newJob, exportFormat);
      onOpenChange(false);
      onJobCreated(
        normalized,
        `Đã tạo tác vụ xuất báo cáo định dạng ${exportFormat}. Báo cáo được tạo bất đồng bộ với TTL 24h và bảo vệ chống CSV Formula Injection.`,
      );
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo tác vụ xuất báo cáo.');
      } else {
        onError('Đã xảy ra lỗi khi xuất báo cáo.');
      }
    } finally {
      setIsExporting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Xuất báo cáo kiểm toán bảo mật
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Chọn định dạng xuất dữ liệu. Hệ thống tự động khử mã thực thi độc hại (CSV Formula
            Injection)
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleTriggerExport} className="space-y-4 py-2 text-xs">
          <fieldset className="space-y-1.5 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1.5">Chọn định dạng tệp:</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {FORMAT_OPTIONS.map(({ value, label, Icon }) => {
                const selected = exportFormat === value;
                return (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={selected}
                    onClick={() => setExportFormat(value)}
                    className={`flex min-h-11 items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                      selected
                        ? 'border-[#222222] bg-[#222222] text-[#ffffff]'
                        : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#222222]'
                    }`}
                  >
                    <Icon size={20} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                    <span>{label}</span>
                  </button>
                );
              })}
            </div>
          </fieldset>

          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-[#717171] text-xs leading-relaxed">
            <div className="flex items-center gap-1.5 text-[#008489] font-semibold">
              <Shield size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>Chống CSV Formula Injection:</span>
            </div>
            <p>
              Mọi trường văn bản bắt đầu bằng các ký tự nguy hiểm (<code>=</code>, <code>+</code>,{' '}
              <code>-</code>, <code>@</code>, tab, xuống dòng) đều được thêm dấu nháy đơn{' '}
              <code>&apos;</code> phía trước để ngăn chặn thực thi mã macro khi mở trong Excel/Calc.
            </p>
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
              text="Bắt đầu xuất tệp"
              icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isExporting}
              disabled={isExporting}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
