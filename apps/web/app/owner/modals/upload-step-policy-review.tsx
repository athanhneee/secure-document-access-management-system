'use client';

import { ShieldCheck, Download, Eye } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import type { useUploadWizard } from '../hooks/use-upload-wizard';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
} from '../types';

interface UploadStepPolicyReviewProps {
  step: 2 | 3;
  wizard: ReturnType<typeof useUploadWizard>;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  currentSelectedLevel: ClassificationLevelLookupItem | undefined;
}

export function UploadStepPolicyReview({
  step,
  wizard,
  departments,
  businessCategories,
  currentSelectedLevel,
}: UploadStepPolicyReviewProps) {
  const {
    docFile,
    docTitle,
    docDescription,
    setDocDescription,
    docDepartmentId,
    docCategoryId,
    docRetentionDate,
    setDocRetentionDate,
  } = wizard;

  if (step === 2) {
    return (
      <div className="space-y-3.5">
        <div className="space-y-1">
          <label htmlFor="doc-desc" className="text-xs font-medium text-[#222222]">
            Mô tả tóm tắt nội dung
          </label>
          <Textarea
            id="doc-desc"
            rows={3}
            value={docDescription}
            onChange={(e) => setDocDescription(e.target.value)}
            placeholder="Nội dung chính và phạm vi sử dụng của tài liệu..."
            className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>

        <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2">
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className="text-[#008489]"
              aria-hidden="true"
            />
            <span className="text-xs font-semibold text-[#222222]">
              Chính sách tải xuống theo mức mật {currentSelectedLevel?.name}
            </span>
          </div>
          <div className="text-xs text-[#717171] leading-relaxed">
            {currentSelectedLevel?.allowDownload ? (
              <div className="text-[#008A05] flex items-center gap-1.5 font-medium">
                <Download size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>
                  Mức mật này <strong>cho phép tải về</strong> dưới dạng PDF có gắn Watermark động
                  chứa danh tính người tải và mã truy vết QR.
                </span>
              </div>
            ) : (
              <div className="text-[#E07912] flex items-center gap-1.5 font-medium">
                <Eye size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>
                  Mức mật này <strong>cấm tải về ngoại tuyến</strong> theo quy chế an toàn dữ liệu.
                  Người dùng chỉ được xem trực tuyến qua Secure Sandbox.
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-1">
          <label htmlFor="doc-retention" className="text-xs font-medium text-[#222222]">
            Thời hạn lưu trữ bảo mật (Retention Date)
          </label>
          <Input
            id="doc-retention"
            type="date"
            value={docRetentionDate}
            onChange={(e) => setDocRetentionDate(e.target.value)}
            className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3 text-xs">
      <div className="rounded-[24px] border border-[#008A05]/20 bg-[#008A05]/5 p-3.5 space-y-2">
        <div className="flex items-center gap-2 text-[#008A05] font-semibold">
          <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>Xác minh trước khi mã hóa lưu trữ</span>
        </div>
        <div className="grid grid-cols-2 gap-1.5 text-[#222222] pt-1 border-t border-[#008A05]/15">
          <span className="text-[#717171]">Tiêu đề:</span>
          <span className="font-semibold text-[#222222]">{docTitle}</span>
          <span className="text-[#717171]">Tệp nguồn:</span>
          <span className="font-bold text-[#222222]">
            {docFile ? `${docFile.name} (${(docFile.size / 1024).toFixed(1)} KB)` : 'Chưa chọn tệp'}
          </span>
          <span className="text-[#717171]">Phòng ban:</span>
          <span>{departments.find((d) => d.id === docDepartmentId)?.name || 'Chưa chọn'}</span>
          <span className="text-[#717171]">Danh mục:</span>
          <span>{businessCategories.find((c) => c.id === docCategoryId)?.name || 'Chưa chọn'}</span>
          <span className="text-[#717171]">Mức độ mật:</span>
          <ClassificationBadge level={currentSelectedLevel?.code ?? 'CONFIDENTIAL'} size="sm" />
          <span className="text-[#717171]">Chính sách tải:</span>
          <span className="font-semibold">
            {currentSelectedLevel?.allowDownload
              ? 'Cho phép tải có watermark'
              : 'Chỉ xem trực tuyến'}
          </span>
          <span className="text-[#717171]">Mã hóa xác thực:</span>
          <span className="font-bold text-[#008A05]">AES-256-GCM / DEK</span>
        </div>
      </div>

      <p className="text-[11px] text-[#717171] leading-relaxed">
        Tài liệu sẽ được quét mã độc, trích xuất magic bytes, phân trang an toàn và lưu vào bộ lưu
        trữ mã hóa độc lập. Dấu bản quyền (Watermark) sẽ được nhúng động mỗi khi có yêu cầu truy
        cập.
      </p>
    </div>
  );
}
