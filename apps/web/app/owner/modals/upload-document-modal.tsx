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
}

export function UploadDocumentModal({
  wizard,
  departments,
  businessCategories,
  classificationLevels,
}: UploadDocumentModalProps) {
  const {
    uploadWizardOpen,
    setUploadWizardOpen,
    wizardStep,
    setWizardStep,
    docFile,
    docTitle,
    docClassificationId,
    isSubmittingDoc,
    handleFinishUpload,
  } = wizard;

  const currentSelectedLevel = classificationLevels.find((l) => l.id === docClassificationId);

  return (
    <Dialog open={uploadWizardOpen} onOpenChange={setUploadWizardOpen}>
      <DialogContent className="max-w-xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Quy trình tải lên tài liệu an toàn (Bước {wizardStep}/3)
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
              'Bước 1: Chọn tập tin nguồn, phòng ban, danh mục và mức độ mật bắt buộc'}
            {wizardStep === 2 &&
              'Bước 2: Xem xét chính sách tải về theo quy định mật và thời hạn bảo quản'}
            {wizardStep === 3 && 'Bước 3: Xác minh thông tin và kích hoạt lưu trữ mã hóa'}
          </DialogDescription>
        </DialogHeader>

        <div className="py-2 space-y-4">
          {wizardStep === 1 ? (
            <UploadStepMetadata
              wizard={wizard}
              departments={departments}
              businessCategories={businessCategories}
              classificationLevels={classificationLevels}
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
              text="Hủy bỏ"
              onClick={() => setUploadWizardOpen(false)}
            />
          )}

          {wizardStep < 3 ? (
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text="Tiếp theo"
              disabled={!docTitle.trim() || !docFile}
              onClick={() => setWizardStep((prev) => (prev + 1) as 2 | 3)}
            />
          ) : (
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text={isSubmittingDoc ? 'Đang tải lên...' : 'Xác nhận tải lên'}
              disabled={isSubmittingDoc || !docFile}
              isLoading={isSubmittingDoc}
              onClick={() => void handleFinishUpload()}
            />
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
