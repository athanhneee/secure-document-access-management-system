'use client';

import { AlertTriangle, CheckCircle2, Lock, ShieldAlert } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Input } from '@/components/ui/input';
import { isClassificationAllowedForClearance } from '../helpers';
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
  userClearanceRank?: number | null | undefined;
  userClearanceCode?: string | null | undefined;
}

export function UploadStepMetadata({
  wizard,
  departments,
  businessCategories,
  classificationLevels,
  userClearanceRank,
  userClearanceCode,
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

  const hasClearanceInfo =
    typeof userClearanceRank === 'number' && Number.isFinite(userClearanceRank);
  const restrictedLevelsCount = hasClearanceInfo
    ? classificationLevels.filter(
        (lvl) => !isClassificationAllowedForClearance(lvl.rank, userClearanceRank),
      ).length
    : 0;
  const hasNoPermittedLevels =
    hasClearanceInfo &&
    classificationLevels.length > 0 &&
    restrictedLevelsCount === classificationLevels.length;

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
          <div className="flex items-center gap-2 pt-1 text-xs text-[#008A05]">
            <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>
              Đã chọn: <strong className="text-[#222222]">{docFile.name}</strong> (
              {(docFile.size / 1024).toFixed(1)} KB)
            </span>
          </div>
        ) : (
          <div className="text-xs text-[#C13515]">
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
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
        />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor="doc-dept" className="text-xs font-medium text-[#222222]">
            Phòng ban chủ quản <span className="text-[#C13515]">*</span>
          </label>
          <select
            id="doc-dept"
            value={String(docDepartmentId)}
            onChange={(e) => setDocDepartmentId(Number(e.target.value))}
            className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            {departments.map((dept) => (
              <option key={dept.id} value={String(dept.id)}>
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
            value={String(docCategoryId)}
            onChange={(e) => setDocCategoryId(Number(e.target.value))}
            className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
          >
            {businessCategories.map((cat) => (
              <option key={cat.id} value={String(cat.id)}>
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
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
        />
      </div>

      <fieldset className="space-y-2 border-0 p-0 m-0 min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <legend className="block text-xs font-medium text-[#222222] p-0">
            Mức độ mật bắt buộc (Mandatory Classification) <span className="text-[#C13515]">*</span>
          </legend>
          {hasClearanceInfo && (
            <span className="inline-flex items-center gap-1.5 text-[11px] text-[#717171]">
              <span>Thẩm quyền của bạn:</span>
              {userClearanceCode ? (
                <ClassificationBadge
                  code={userClearanceCode}
                  rank={userClearanceRank}
                  showRank
                  size="sm"
                />
              ) : (
                <span className="inline-flex items-center gap-1 font-semibold text-[#C13515]">
                  <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>CHƯA CẤP · R0</span>
                </span>
              )}
            </span>
          )}
        </div>

        {hasNoPermittedLevels && (
          <div
            role="alert"
            className="rounded-[18px] border border-[#C13515]/30 bg-[#f7f7f7] p-3 flex items-start gap-2 text-xs text-[#222222]"
          >
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515] mt-0.5"
              aria-hidden="true"
            />
            <div className="space-y-0.5 leading-relaxed">
              <div className="font-semibold text-[#C13515]">
                Tài khoản chưa được cấp thẩm quyền bảo mật (CLEARANCE_LEVEL = Rank 0)
              </div>
              <p className="text-[#717171]">
                Theo nguyên tắc Bell-LaPadula, bạn chưa thể tải lên tài liệu ở bất kỳ mức mật nào.
                Vui lòng liên hệ Quản trị viên hệ thống để gán cấp độ thẩm tra tại mục Quản lý tài
                khoản.
              </p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {classificationLevels.map((level) => {
            const isAboveClearance = !isClassificationAllowedForClearance(
              level.rank,
              userClearanceRank,
            );
            const isSelected =
              !isAboveClearance && String(docClassificationId) === String(level.id);
            return (
              <button
                key={level.id}
                type="button"
                disabled={isAboveClearance}
                title={
                  isAboveClearance
                    ? `Vượt cấp thẩm quyền Bell-LaPadula (yêu cầu Rank ${level.rank}, tài khoản hiện tại Rank ${userClearanceRank ?? 0})`
                    : `Chọn mức độ mật ${level.name} (Rank ${level.rank})`
                }
                aria-label={
                  isAboveClearance
                    ? `${level.name} (${level.code}) — Bị khóa do vượt cấp thẩm quyền (yêu cầu Rank ${level.rank})`
                    : `Chọn mức độ mật ${level.name} (${level.code})`
                }
                aria-pressed={isSelected}
                onClick={() => {
                  if (!isAboveClearance) {
                    setDocClassificationId(Number(level.id));
                  }
                }}
                className={`min-h-11 flex flex-col items-center justify-center gap-0.5 py-2 px-3 rounded-full border text-center transition-all duration-200 ${
                  isAboveClearance
                    ? 'border-[#ebebeb] bg-[#f7f7f7] opacity-55 cursor-not-allowed'
                    : isSelected
                      ? 'border-[#FF385C] bg-[#FF385C]/10 ring-1 ring-[#FF385C] cursor-pointer'
                      : 'border-[#ebebeb] bg-[#ffffff] hover:bg-[#f7f7f7] hover:border-[#dddddd] cursor-pointer'
                }`}
              >
                <ClassificationBadge level={level.code} size="sm" />
                {isAboveClearance && (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#717171]">
                    <Lock size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Cần R{level.rank}</span>
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {!hasNoPermittedLevels && restrictedLevelsCount > 0 && hasClearanceInfo && (
          <div className="rounded-[16px] border border-[#E07912]/35 bg-[#f7f7f7] px-3 py-2 flex items-start gap-2 text-[11px] text-[#717171]">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912] mt-0.5"
              aria-hidden="true"
            />
            <span>
              Các mức mật cao hơn{' '}
              <strong className="text-[#222222]">Rank {userClearanceRank}</strong> đã bị giới hạn
              theo nguyên tắc Bell-LaPadula để tránh từ chối khi xác nhận tải lên.
            </span>
          </div>
        )}
      </fieldset>
    </div>
  );
}
