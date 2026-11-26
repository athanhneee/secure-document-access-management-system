'use client';

import { AlertTriangle, CheckCircle2, Lock, ShieldAlert } from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
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
    fileValidationError,
    docCodeError,
    subjectReadiness,
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
      {!subjectReadiness.ready && subjectReadiness.blockingReason && (
        <div
          role="alert"
          className="rounded-[18px] border border-[#ebebeb] bg-[#f7f7f7] p-3 flex items-start gap-2 text-xs text-[#222222]"
        >
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#C13515] mt-0.5"
            aria-hidden="true"
          />
          <div className="space-y-0.5 leading-relaxed">
            <div className="font-semibold text-[#C13515]">Chưa đủ điều kiện tải lên tài liệu</div>
            <p className="text-[#717171]">{subjectReadiness.blockingReason}</p>
          </div>
        </div>
      )}

      <div className="space-y-1">
        <label htmlFor="doc-file-upload" className="text-xs font-medium text-[#222222]">
          Chọn tệp tài liệu (PDF, DOCX, XLSX, PPTX · tối đa 50 MB){' '}
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
              setDocTitle(file.name.replace(/\.[^/.]+$/, '').slice(0, 255));
            }
          }}
          className="w-full text-xs text-[#717171] file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-[#f7f7f7] file:text-xs file:font-medium file:text-[#222222] hover:file:bg-[#ebebeb] cursor-pointer"
        />
        {docFile ? (
          fileValidationError ? (
            <div role="alert" className="flex items-start gap-2 pt-1 text-xs text-[#C13515]">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <span>{fileValidationError}</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 pt-1 text-xs text-[#008A05]">
              <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>
                Đã chọn: <strong className="text-[#222222]">{docFile.name}</strong> (
                {(docFile.size / 1024).toFixed(1)} KB)
              </span>
            </div>
          )
        ) : (
          <div className="text-xs text-[#717171]">
            Vui lòng chọn một tệp tài liệu hợp lệ (không rỗng, tối đa 50 MB) trước khi tiếp tục.
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
          maxLength={255}
          value={docTitle}
          onChange={(e) => setDocTitle(e.target.value)}
          placeholder="Ví dụ: Báo cáo tài chính quý 3/2026"
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0]"
        />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor="doc-dept" className="text-xs font-medium text-[#222222]">
            Phòng ban chủ quản <span className="text-[#C13515]">*</span>
          </label>
          <Select
            id="doc-dept"
            disabled={subjectReadiness.missingDepartment || departments.length === 0}
            value={departments.length === 0 ? '' : String(docDepartmentId)}
            onChange={(e) => setDocDepartmentId(Number(e.target.value))}
          >
            {departments.length === 0 ? (
              <option value="">Không có phòng ban trong phạm vi tải lên</option>
            ) : (
              departments.map((dept) => (
                <option key={dept.id} value={String(dept.id)}>
                  {dept.name}
                </option>
              ))
            )}
          </Select>
        </div>

        <div className="space-y-1">
          <label htmlFor="doc-category" className="text-xs font-medium text-[#222222]">
            Danh mục nghiệp vụ <span className="text-[#C13515]">*</span>
          </label>
          <Select
            id="doc-category"
            value={String(docCategoryId)}
            onChange={(e) => setDocCategoryId(Number(e.target.value))}
          >
            {businessCategories.map((cat) => (
              <option key={cat.id} value={String(cat.id)}>
                {cat.name}
              </option>
            ))}
          </Select>
        </div>
      </div>

      <div className="space-y-1">
        <label htmlFor="doc-code" className="text-xs font-medium text-[#222222]">
          Mã tài liệu (để trống để hệ thống tự cấp)
        </label>
        <Input
          id="doc-code"
          maxLength={60}
          value={docCode}
          onChange={(e) => setDocCode(e.target.value)}
          aria-invalid={Boolean(docCodeError)}
          aria-describedby={docCodeError ? 'doc-code-error' : undefined}
          placeholder="VD: TC-2026-001"
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0]"
        />
        {docCodeError && (
          <p id="doc-code-error" role="alert" className="text-xs text-[#C13515]">
            {docCodeError}
          </p>
        )}
      </div>

      <fieldset className="space-y-2 border-0 p-0 m-0 min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <legend className="block text-xs font-medium text-[#222222] p-0">
            Mức độ mật bắt buộc <span className="text-[#C13515]">*</span>
          </legend>
          {hasClearanceInfo && (
            <span className="inline-flex items-center gap-1.5 text-[11px] text-[#717171]">
              <span>Cấp thẩm quyền của bạn:</span>
              {userClearanceCode ? (
                <ClassificationBadge
                  code={userClearanceCode}
                  rank={userClearanceRank}
                  subject="user"
                  showRank
                  size="sm"
                />
              ) : (
                <span className="inline-flex items-center gap-1 font-semibold text-[#C13515]">
                  <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>CHƯA CẤP · Cấp 0</span>
                </span>
              )}
            </span>
          )}
        </div>

        {hasNoPermittedLevels && (
          <div
            role="alert"
            className="rounded-[18px] border border-[#ebebeb] bg-[#f7f7f7] p-3 flex items-start gap-2 text-xs text-[#222222]"
          >
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515] mt-0.5"
              aria-hidden="true"
            />
            <div className="space-y-0.5 leading-relaxed">
              <div className="font-semibold text-[#C13515]">
                Tài khoản chưa được cấp thẩm quyền bảo mật
              </div>
              <p className="text-[#717171]">
                Bạn hiện chưa thể tải lên tài liệu ở mức độ mật nào. Vui lòng liên hệ quản trị viên
                hệ thống để được gán cấp thẩm quyền bảo mật phù hợp.
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
                    ? `Vượt quá cấp thẩm quyền bảo mật (yêu cầu Cấp ${level.rank}, hiện tại Cấp ${userClearanceRank ?? 0})`
                    : `Chọn mức độ mật ${level.name} (Cấp ${level.rank})`
                }
                aria-label={
                  isAboveClearance
                    ? `${level.name} — Bị giới hạn do vượt cấp thẩm quyền (yêu cầu Cấp ${level.rank})`
                    : `Chọn mức độ mật ${level.name}`
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
                      ? 'border-[#222222] bg-[#f7f7f7] ring-1 ring-[#222222] cursor-pointer'
                      : 'border-[#ebebeb] bg-[#ffffff] hover:bg-[#f7f7f7] hover:border-[#dddddd] cursor-pointer'
                }`}
              >
                <ClassificationBadge level={level.code} size="sm" />
                {isAboveClearance && (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#717171]">
                    <Lock size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Cần Cấp {level.rank}</span>
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {!hasNoPermittedLevels && restrictedLevelsCount > 0 && hasClearanceInfo && (
          <div className="flex items-start gap-2 text-[11px] text-[#717171] pt-0.5">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912] mt-0.5"
              aria-hidden="true"
            />
            <span>
              Các mức độ mật cao hơn{' '}
              <strong className="text-[#222222]">Cấp {userClearanceRank}</strong> được giới hạn theo
              cấp thẩm quyền bảo mật hiện tại của tài khoản.
            </span>
          </div>
        )}
      </fieldset>
    </div>
  );
}
