'use client';

import { useMemo, useState, type FormEvent } from 'react';
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
import { formatExportFormatLabel, formatExportTypeLabel } from '@/lib/ui-labels';
import { buildExportFilterParamsFromAuditFilters, normalizeExportJob } from '../helpers';
import type { AuditTrailFilters, ExportFormat, ExportJobItem, ExportReportType } from '../types';

interface ExportReportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  canExportAuditLogs: boolean;
  canExportSystemReport: boolean;
  canExportSecurityAlerts: boolean;
  activeAuditFilters: AuditTrailFilters;
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
 * Thuật toán: Khởi Tạo Tác Vụ Xuất Báo Cáo Tuân Thủ Đa Miền Kèm Bộ Lọc Đang Áp Dụng (`ExportReportModal`)
 * Mục đích:
 *   - Chỉ hiển thị các miền dữ liệu mà kiểm toán viên được cấp quyền (`AUDIT_LOGS`, `SYSTEM_REPORT`, `SECURITY_ALERTS`) để tránh lỗi 403 khi chỉ có `SYSTEM_REPORT:EXPORT`.
 *   - Cho phép đính kèm bộ lọc nhật ký đang chọn vào `filterParams` và khóa nút Hủy khi đang gửi yêu cầu.
 */
export function ExportReportModal({
  open,
  onOpenChange,
  canExportAuditLogs,
  canExportSystemReport,
  canExportSecurityAlerts,
  activeAuditFilters,
  onClearError,
  onJobCreated,
  onError,
}: ExportReportModalProps) {
  const allowedExportTypes = useMemo<ExportReportType[]>(() => {
    const types: ExportReportType[] = [];
    if (canExportAuditLogs) types.push('AUDIT_LOGS');
    if (canExportSystemReport) types.push('SYSTEM_REPORT');
    if (canExportSecurityAlerts) types.push('SECURITY_ALERTS');
    return types;
  }, [canExportAuditLogs, canExportSecurityAlerts, canExportSystemReport]);

  const [selectedType, setSelectedType] = useState<ExportReportType>('AUDIT_LOGS');
  const exportType: ExportReportType = allowedExportTypes.includes(selectedType)
    ? selectedType
    : (allowedExportTypes[0] ?? 'AUDIT_LOGS');

  const [exportFormat, setExportFormat] = useState<ExportFormat>('CSV');
  const [applyCurrentFilters, setApplyCurrentFilters] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const computedFilterParams = useMemo(
    () => buildExportFilterParamsFromAuditFilters(activeAuditFilters),
    [activeAuditFilters],
  );
  const activeFilterCount = Object.keys(computedFilterParams).length;

  async function handleTriggerExport(e: FormEvent) {
    e.preventDefault();
    if (allowedExportTypes.length === 0) {
      onError('Tài khoản của bạn không có quyền xuất báo cáo.');
      return;
    }

    setIsExporting(true);
    onClearError();

    const filterParams =
      exportType === 'AUDIT_LOGS' && applyCurrentFilters ? computedFilterParams : {};

    try {
      const newJob = await apiClient<ExportJobItem>('/reports/export', {
        method: 'POST',
        body: JSON.stringify({
          exportType,
          format: exportFormat,
          filterParams,
        }),
      });

      const normalized = normalizeExportJob(newJob, exportFormat);
      onOpenChange(false);
      const statusText =
        normalized.status === 'COMPLETED'
          ? 'Tệp báo cáo đã sẵn sàng để tải về (hiệu lực 24 giờ).'
          : 'Yêu cầu đã được đưa vào hàng đợi xử lý nền và sẽ tự động cập nhật khi sẵn sàng (hiệu lực 24 giờ).';
      onJobCreated(
        normalized,
        `Đã khởi tạo ${formatExportTypeLabel(exportType).toLowerCase()} định dạng ${formatExportFormatLabel(exportFormat)}. ${statusText}`,
      );
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo yêu cầu xuất báo cáo.');
      } else {
        onError('Đã xảy ra lỗi khi xuất báo cáo.');
      }
    } finally {
      setIsExporting(false);
    }
  }

  const isSpreadsheetFormat = exportFormat === 'CSV' || exportFormat === 'EXCEL';

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !isExporting && onOpenChange(nextOpen)}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Xuất báo cáo tuân thủ
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Chọn loại báo cáo và định dạng tệp xuất theo quyền hạn được cấp.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleTriggerExport} className="space-y-4 py-2 text-xs">
          <div className="space-y-1.5">
            <label htmlFor="auditor-export-type" className="font-medium text-[#222222] block">
              Loại báo cáo
            </label>
            <select
              id="auditor-export-type"
              value={exportType}
              disabled={isExporting || allowedExportTypes.length <= 1}
              onChange={(e) => setSelectedType(e.target.value as ExportReportType)}
              className="min-h-11 sm:h-10 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:opacity-70"
            >
              {allowedExportTypes.map((typeOption) => (
                <option key={typeOption} value={typeOption}>
                  {formatExportTypeLabel(typeOption)}
                </option>
              ))}
            </select>
          </div>

          <fieldset className="space-y-1.5 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1.5">Chọn định dạng tệp</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {FORMAT_OPTIONS.map(({ value, label, Icon }) => {
                const selected = exportFormat === value;
                return (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={selected}
                    disabled={isExporting}
                    onClick={() => setExportFormat(value)}
                    className={`flex min-h-11 items-center justify-center gap-2 px-4 py-2.5 rounded-full border text-xs font-semibold transition-all duration-100 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer disabled:opacity-60 ${
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

          {exportType === 'AUDIT_LOGS' && activeFilterCount > 0 && (
            <label
              htmlFor="auditor-apply-filters-checkbox"
              className="flex items-start gap-2.5 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 cursor-pointer"
            >
              <input
                id="auditor-apply-filters-checkbox"
                type="checkbox"
                checked={applyCurrentFilters}
                disabled={isExporting}
                onChange={(e) => setApplyCurrentFilters(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#FF385C] cursor-pointer"
              />
              <span className="text-[#222222] leading-relaxed">
                Áp dụng <strong>{activeFilterCount}</strong> bộ lọc nhật ký đang chọn trên màn hình
                (bỏ chọn để xuất toàn bộ tối đa 1.000 bản ghi gần nhất).
              </span>
            </label>
          )}

          {isSpreadsheetFormat && (
            <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-[#717171] text-xs leading-relaxed">
              <div className="flex items-center gap-1.5 text-[#008489] font-semibold">
                <Shield size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Bảo vệ an toàn bảng tính</span>
              </div>
              <p>
                Nội dung văn bản trong tệp bảng tính được tự động chuẩn hóa để ngăn thực thi công
                thức ngoài ý muốn khi mở trên Excel hoặc các phần mềm bảng tính khác.
              </p>
            </div>
          )}

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={isExporting}
              onClick={() => onOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Bắt đầu xuất tệp"
              icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isExporting}
              disabled={isExporting || allowedExportTypes.length === 0}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
