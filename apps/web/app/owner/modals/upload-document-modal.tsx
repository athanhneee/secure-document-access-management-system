'use client';

import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { isClassificationAllowedForClearance } from '../helpers';
import type { useUploadWizard } from '../hooks/use-upload-wizard';
import { UploadStepMetadata } from './upload-step-metadata';
import { UploadStepPolicyReview } from './upload-step-policy-review';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
} from '../types';

interface UploadDocumentModalProps {
  wizard: ReturnType<typeof useUploadWizard>;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  classificationLevels: ClassificationLevelLookupItem[];
  userClearanceRank?: number | null | undefined;
  userClearanceCode?: string | null | undefined;
}

export function UploadDocumentModal({
  wizard,
  departments,
  businessCategories,
  classificationLevels,
  userClearanceRank,
  userClearanceCode,
}: UploadDocumentModalProps) {
  const {
    uploadWizardOpen,
    setUploadWizardOpen,
    wizardStep,
    setWizardStep,
    docFile,
    docTitle,
    docClassificationId,
    retentionDateError,
    subjectReadiness,
    isSubmittingDoc,
    handleNextStep,
    handleFinishUpload,
  } = wizard;

  const currentSelectedLevel = classificationLevels.find(
    (l) => String(l.id) === String(docClassificationId),
  );
  const isSelectedAboveClearance =
    currentSelectedLevel !== undefined &&
    !isClassificationAllowedForClearance(currentSelectedLevel.rank, userClearanceRank);
  const hasNoUploadClearance =
    typeof userClearanceRank === 'number' &&
    classificationLevels.length > 0 &&
    classificationLevels.every(
      (l) => !isClassificationAllowedForClearance(l.rank, userClearanceRank),
    );
  const isSubjectBlocked = !subjectReadiness.ready;

  return (
    <Dialog open={uploadWizardOpen} onOpenChange={setUploadWizardOpen}>
      <DialogContent className="max-w-xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Tải lên tài liệu mới (Bước {wizardStep}/3)
            </DialogTitle>
            <div className="flex gap-1.5">
              {[1, 2, 3].map((step) => (
                <div
                  key={step}
                  className={`h-2 w-6 rounded-full transition-all ${
                    wizardStep === step
                      ? 'bg-[#FF385C]'
                      : wizardStep > step
                        ? 'bg-[#FF385C]/50'
                        : 'bg-[#ebebeb]'
                  }`}
                />
              ))}
            </div>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            {wizardStep === 1 &&
              'Chọn tệp tài liệu, phòng ban, danh mục nghiệp vụ và mức độ mật áp dụng.'}
            {wizardStep === 2 &&
              'Xem lại chính sách tải về theo mức độ mật và thiết lập thời hạn lưu trữ.'}
            {wizardStep === 3 && 'Kiểm tra lại toàn bộ thông tin trước khi xác nhận tải lên.'}
          </DialogDescription>
        </DialogHeader>

        <div className="py-2 space-y-4">
          {wizardStep === 1 ? (
            <UploadStepMetadata
              wizard={wizard}
              departments={departments}
              businessCategories={businessCategories}
              classificationLevels={classificationLevels}
              userClearanceRank={userClearanceRank}
              userClearanceCode={userClearanceCode}
            />
          ) : (
            <UploadStepPolicyReview
              step={wizardStep}
              wizard={wizard}
              departments={departments}
              businessCategories={businessCategories}
              currentSelectedLevel={currentSelectedLevel}
            />
          )}
        </div>

        <DialogFooter className="flex justify-between sm:justify-between pt-2">
          {wizardStep > 1 ? (
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              text="Quay lại"
              onClick={() => setWizardStep((prev) => (prev - 1) as 1 | 2)}
            />
          ) : (
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              onClick={() => setUploadWizardOpen(false)}
            />
          )}

          {wizardStep < 3 ? (
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text="Tiếp theo"
              disabled={
                !docTitle.trim() ||
                !docFile ||
                isSubjectBlocked ||
                hasNoUploadClearance ||
                isSelectedAboveClearance ||
                (wizardStep === 2 && Boolean(retentionDateError))
              }
              onClick={handleNextStep}
            />
          ) : (
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text={isSubmittingDoc ? 'Đang tải lên…' : 'Xác nhận tải lên'}
              disabled={
                isSubmittingDoc ||
                !docFile ||
                isSubjectBlocked ||
                hasNoUploadClearance ||
                isSelectedAboveClearance ||
                Boolean(retentionDateError)
              }
              isLoading={isSubmittingDoc}
              onClick={() => void handleFinishUpload()}
            />
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
