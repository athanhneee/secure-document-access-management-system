'use client';

import { useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  evaluateUploadSubjectReadiness,
  getMinRetentionDate,
  isClassificationAllowedForClearance,
  resolveUploadWizardDefaults,
  validateRetentionDateInput,
} from '../helpers';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
} from '../types';

import type { OwnerTab } from './use-owner-data';

interface UseUploadWizardParams {
  userDepartmentId?: string | number | null | undefined;
  userClearanceRank?: number | null | undefined;
  userStatus?: string | null | undefined;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  classificationLevels: ClassificationLevelLookupItem[];
  ensureUploadLookups?: () => Promise<void>;
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Quy trình Tải lên Tài liệu 3 Bước Bắt buộc Gắn Nhãn Mật & Tải Lười Danh Mục (`useUploadWizard`)
 * Khởi tạo phòng ban/danh mục/mức mật mặc định suy dẫn tự động ngay khi danh mục tra cứu hoàn tất tải lười, tải lên multipart, gắn phiên bản hiện hành và kích hoạt tài liệu `ACTIVE`.
 */
export function useUploadWizard({
  userDepartmentId,
  userClearanceRank,
  userStatus,
  departments,
  businessCategories,
  classificationLevels,
  ensureUploadLookups,
  refreshData,
  setMessage,
  setErrorMessage,
}: UseUploadWizardParams) {
  const [uploadWizardOpen, setUploadWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState<1 | 2 | 3>(1);
  const [docFile, setDocFile] = useState<File | null>(null);
  const [docTitle, setDocTitle] = useState('');
  const [docCode, setDocCode] = useState('');
  const [docDescription, setDocDescription] = useState('');
  const [docDepartmentOverride, setDocDepartmentOverride] = useState<number | null>(null);
  const [docCategoryOverride, setDocCategoryOverride] = useState<number | null>(null);
  const [docClassificationOverride, setDocClassificationOverride] = useState<number | null>(null);
  const [docRetentionDate, setDocRetentionDate] = useState('');
  const [isSubmittingDoc, setIsSubmittingDoc] = useState(false);

  const wizardDefaults = resolveUploadWizardDefaults({
    userDepartmentId,
    userClearanceRank,
    departments,
    businessCategories,
    classificationLevels,
  });
  const docDepartmentId = docDepartmentOverride ?? wizardDefaults.departmentId;
  const docCategoryId = docCategoryOverride ?? wizardDefaults.categoryId;
  const docClassificationId = docClassificationOverride ?? wizardDefaults.classificationId;

  const setDocDepartmentId = (value: number) => setDocDepartmentOverride(value);
  const setDocCategoryId = (value: number) => setDocCategoryOverride(value);
  const setDocClassificationId = (value: number) => setDocClassificationOverride(value);

  const minRetentionDate = getMinRetentionDate();
  const retentionDateError = validateRetentionDateInput(docRetentionDate);
  const subjectReadiness = evaluateUploadSubjectReadiness({
    departmentId: userDepartmentId,
    clearanceRank: userClearanceRank,
    status: userStatus,
  });

  function resolveClearanceError(): string | null {
    if (!subjectReadiness.ready && subjectReadiness.blockingReason) {
      return subjectReadiness.blockingReason;
    }
    const chosenLevel = classificationLevels.find(
      (l) => String(l.id) === String(docClassificationId),
    );
    if (chosenLevel && !isClassificationAllowedForClearance(chosenLevel.rank, userClearanceRank)) {
      return `Cấp thẩm quyền hiện tại (Cấp ${userClearanceRank ?? 0}) chưa đủ cho mức độ mật ${chosenLevel.name} (Cấp ${chosenLevel.rank}).`;
    }
    return null;
  }

  function handleNextStep() {
    if (wizardStep === 1) {
      if (!docFile) {
        setErrorMessage('Vui lòng chọn tệp tài liệu trước khi tiếp tục.');
        return;
      }
      if (!docTitle.trim()) {
        setErrorMessage('Tiêu đề tài liệu không được để trống.');
        return;
      }
      const clearanceErr = resolveClearanceError();
      if (clearanceErr) {
        setErrorMessage(clearanceErr);
        return;
      }
      setErrorMessage(null);
      setWizardStep(2);
      return;
    }

    if (wizardStep === 2) {
      const retentionErr = validateRetentionDateInput(docRetentionDate);
      if (retentionErr) {
        setErrorMessage(retentionErr);
        return;
      }
      setErrorMessage(null);
      setWizardStep(3);
    }
  }

  function openUploadWizard() {
    setErrorMessage(null);
    void ensureUploadLookups?.();
    if (!docFile && !docTitle.trim()) {
      setDocDepartmentOverride(null);
      setDocCategoryOverride(null);
      setDocClassificationOverride(null);
    }
    setWizardStep(1);
    setUploadWizardOpen(true);
  }

  async function handleFinishUpload() {
    if (!docFile) {
      setErrorMessage('Vui lòng chọn tệp tài liệu trước khi tiếp tục.');
      setWizardStep(1);
      return;
    }

    if (!docTitle.trim()) {
      setErrorMessage('Tiêu đề tài liệu không được để trống.');
      setWizardStep(1);
      return;
    }

    const clearanceErr = resolveClearanceError();
    if (clearanceErr) {
      setErrorMessage(clearanceErr);
      setWizardStep(1);
      return;
    }

    const retentionErr = validateRetentionDateInput(docRetentionDate);
    if (retentionErr) {
      setErrorMessage(retentionErr);
      setWizardStep(2);
      return;
    }

    setIsSubmittingDoc(true);
    setErrorMessage(null);

    try {
      const formData = new FormData();
      formData.append('title', docTitle.trim());
      if (docCode.trim()) {
        formData.append('documentCode', docCode.trim());
      }
      formData.append('departmentId', String(docDepartmentId));
      formData.append('classificationLevelId', String(docClassificationId));
      formData.append('businessCategoryId', String(docCategoryId));
      if (docDescription.trim()) {
        formData.append('description', docDescription.trim());
      }
      if (docRetentionDate) {
        formData.append('retentionUntil', docRetentionDate);
      }
      formData.append('changeNote', 'Tải lên tài liệu ban đầu');
      formData.append('file', docFile);

      const uploadRes = await apiClient<{
        documentId: string;
        versionNo: number;
        originalFilename: string;
        scanStatus: string;
        status: string;
      }>('/documents/upload', {
        method: 'POST',
        body: formData,
      });

      const docId = uploadRes.documentId;

      try {
        await apiClient(`/documents/${docId}/current-version`, {
          method: 'POST',
          body: JSON.stringify({ versionNo: uploadRes.versionNo ?? 1 }),
        });
      } catch (verErr) {
        console.warn('Could not explicitly set current-version:', verErr);
      }

      let activated = false;
      try {
        await apiClient(`/documents/${docId}/activate`, {
          method: 'POST',
        });
        activated = true;
      } catch (actErr) {
        console.warn('Could not automatically activate document, leaving as DRAFT:', actErr);
      }

      const selectedLevel = classificationLevels.find(
        (l) => String(l.id) === String(docClassificationId),
      );
      const levelName = selectedLevel?.name ?? 'Mật';
      setMessage(
        activated
          ? `Tài liệu "${docTitle.trim()}" (${docFile.name}) đã được tải lên và kích hoạt thành công với mức độ mật ${levelName}.`
          : `Tài liệu "${docTitle.trim()}" (${docFile.name}) đã được tải lên ở trạng thái bản nháp (mức độ mật ${levelName}). Bạn có thể kích hoạt thủ công trong danh sách.`,
      );
      setUploadWizardOpen(false);
      setWizardStep(1);
      setDocFile(null);
      setDocTitle('');
      setDocCode('');
      setDocDescription('');
      setDocRetentionDate('');
      setDocDepartmentOverride(null);
      setDocCategoryOverride(null);
      setDocClassificationOverride(null);
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải lên tài liệu mới.');
      } else {
        setErrorMessage('Đã xảy ra lỗi trong quá trình tải lên tài liệu.');
      }
    } finally {
      setIsSubmittingDoc(false);
    }
  }

  return {
    uploadWizardOpen,
    setUploadWizardOpen,
    wizardStep,
    setWizardStep,
    docFile,
    setDocFile,
    docTitle,
    setDocTitle,
    docCode,
    setDocCode,
    docDescription,
    setDocDescription,
    docDepartmentId,
    setDocDepartmentId,
    docCategoryId,
    setDocCategoryId,
    docClassificationId,
    setDocClassificationId,
    docRetentionDate,
    setDocRetentionDate,
    minRetentionDate,
    retentionDateError,
    subjectReadiness,
    isSubmittingDoc,
    openUploadWizard,
    handleNextStep,
    handleFinishUpload,
  };
}
