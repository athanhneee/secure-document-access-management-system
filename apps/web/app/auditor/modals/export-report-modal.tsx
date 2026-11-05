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
            {/* CONFLICT-RESOLVED: Chuyển các nút chọn định dạng xuất báo cáo sang rounded-full chuẩn pill theo rules/ui-design-system.md §4 */}
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                aria-pressed={exportFormat === 'CSV'}
                onClick={() => setExportFormat('CSV')}
                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  exportFormat === 'CSV'
                    ? 'border-[#FF385C] bg-[#FF385C]/15 text-[#FF385C]'
                    : 'border-[#ebebeb] bg-[#f7f7f7] text-[#717171] hover:border-[#dddddd]'
                }`}
              >
                <FileSpreadsheet
                  size={20}
                  strokeWidth={1.75}
                  className="text-[#FF385C] shrink-0"
                  aria-hidden="true"
                />
                <span>CSV</span>
              </button>
              <button
                type="button"
                aria-pressed={exportFormat === 'EXCEL'}
                onClick={() => setExportFormat('EXCEL')}
                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  exportFormat === 'EXCEL'
                    ? 'border-[#008A05] bg-[#008A05]/15 text-[#008A05]'
                    : 'border-[#ebebeb] bg-[#f7f7f7] text-[#717171] hover:border-[#dddddd]'
                }`}
              >
                <FileSpreadsheet
                  size={20}
                  strokeWidth={1.75}
                  className="text-[#008A05] shrink-0"
                  aria-hidden="true"
                />
                <span>Excel (.xlsx)</span>
              </button>
              <button
                type="button"
                aria-pressed={exportFormat === 'JSON'}
                onClick={() => setExportFormat('JSON')}
                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  exportFormat === 'JSON'
                    ? 'border-[#FF385C] bg-[#FF385C]/15 text-[#FF385C]'
                    : 'border-[#ebebeb] bg-[#f7f7f7] text-[#717171] hover:border-[#dddddd]'
                }`}
              >
                <FileJson
                  size={20}
                  strokeWidth={1.75}
                  className="text-[#E07912] shrink-0"
                  aria-hidden="true"
                />
                <span>JSON</span>
              </button>
              <button
                type="button"
                aria-pressed={exportFormat === 'PDF'}
                onClick={() => setExportFormat('PDF')}
                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                  exportFormat === 'PDF'
                    ? 'border-[#C13515] bg-[#C13515]/15 text-[#C13515]'
                    : 'border-[#ebebeb] bg-[#f7f7f7] text-[#717171] hover:border-[#dddddd]'
                }`}
              >
                <FileText
                  size={20}
                  strokeWidth={1.75}
                  className="text-[#C13515] shrink-0"
                  aria-hidden="true"
                />
                <span>PDF</span>
              </button>
            </div>
          </fieldset>

          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-[#717171] text-[11px] leading-relaxed">
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
