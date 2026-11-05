'use client';

import { CheckCircle2 } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Input } from '@/components/ui/input';
import type { useUploadWizard } from '../hooks/use-upload-wizard';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
} from '../types';

interface UploadStepMetadataProps {
  wizard: ReturnType<typeof useUploadWizard>;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  classificationLevels: ClassificationLevelLookupItem[];
}

export function UploadStepMetadata({
  wizard,
  departments,
  businessCategories,
  classificationLevels,
}: UploadStepMetadataProps) {
  const {
    docFile,
    setDocFile,
    docTitle,
    setDocTitle,
    docDepartmentId,
    setDocDepartmentId,
    docCategoryId,
    setDocCategoryId,
    docCode,
    setDocCode,
    docClassificationId,
    setDocClassificationId,
  } = wizard;

  return (
    <div className="space-y-3.5">
      <div className="space-y-1">
        <label htmlFor="doc-file-upload" className="text-xs font-medium text-[#222222]">
          Chọn tệp tài liệu (Bắt buộc: PDF, DOCX, XLSX, PPTX){' '}
          <span className="text-[#C13515]">*</span>
        </label>
        <input
          id="doc-file-upload"
          type="file"
          required
          accept=".pdf,.docx,.xlsx,.pptx"
          onChange={(e) => {
            const file = e.target.files?.[0] || null;
            setDocFile(file);
            if (file && !docTitle) {
              setDocTitle(file.name.replace(/\.[^/.]+$/, ''));
            }
          }}
          className="w-full text-xs text-[#717171] file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-[#f7f7f7] file:text-xs file:font-medium file:text-[#222222] hover:file:bg-[#ebebeb] cursor-pointer"
        />
        {docFile ? (
          <div className="flex items-center gap-2 pt-1 text-[11px] text-[#008A05]">
            <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>
              Đã chọn: <strong className="text-[#222222]">{docFile.name}</strong> (
              {(docFile.size / 1024).toFixed(1)} KB)
            </span>
          </div>
        ) : (
          <div className="text-[11px] text-[#C13515]">
            * Bạn phải chọn một tệp tài liệu trước khi tiếp tục
          </div>
        )}
      </div>

      <div className="space-y-1">
        <label htmlFor="doc-title" className="text-xs font-medium text-[#222222]">
          Tiêu đề tài liệu <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="doc-title"
          required
          value={docTitle}
          onChange={(e) => setDocTitle(e.target.value)}
          placeholder="Ví dụ: Báo cáo tài chính quý 3/2026"
          className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor="doc-dept" className="text-xs font-medium text-[#222222]">
            Phòng ban chủ quản <span className="text-[#C13515]">*</span>
          </label>
          <select
            id="doc-dept"
            value={docDepartmentId}
            onChange={(e) => setDocDepartmentId(Number(e.target.value))}
            className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            {departments.map((dept) => (
              <option key={dept.id} value={dept.id}>
                {dept.name} ({dept.code})
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-1">
          <label htmlFor="doc-category" className="text-xs font-medium text-[#222222]">
            Danh mục nghiệp vụ <span className="text-[#C13515]">*</span>
          </label>
          <select
            id="doc-category"
            value={docCategoryId}
            onChange={(e) => setDocCategoryId(Number(e.target.value))}
            className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            {businessCategories.map((cat) => (
              <option key={cat.id} value={cat.id}>
                {cat.name} ({cat.code})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="space-y-1">
        <label htmlFor="doc-code" className="text-xs font-medium text-[#222222]">
          Mã số tài liệu (Để trống để hệ thống tự cấp)
        </label>
        <Input
          id="doc-code"
          value={docCode}
          onChange={(e) => setDocCode(e.target.value)}
          placeholder="DOC-TC-2026-001"
          className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
        />
      </div>

      <fieldset className="space-y-2 border-0 p-0 m-0 min-w-0">
        <legend className="block text-xs font-medium text-[#222222] mb-2">
          Mức độ mật bắt buộc (Mandatory Classification) <span className="text-[#C13515]">*</span>
        </legend>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {classificationLevels.map((level) => (
            <button
              key={level.id}
              type="button"
              aria-label={`Chọn mức độ mật ${level.name} (${level.code})`}
              aria-pressed={docClassificationId === level.id}
              onClick={() => setDocClassificationId(level.id)}
              className={`flex flex-col items-center justify-center py-2 px-3 rounded-full border text-center transition-all duration-200 cursor-pointer ${
                docClassificationId === level.id
                  ? 'border-[#FF385C] bg-[#FF385C]/10 ring-1 ring-[#FF385C]'
                  : 'border-[#ebebeb] bg-[#ffffff] hover:bg-[#f7f7f7] hover:border-[#dddddd]'
              }`}
            >
              <ClassificationBadge level={level.code} size="sm" />
            </button>
          ))}
        </div>
      </fieldset>
    </div>
  );
}
