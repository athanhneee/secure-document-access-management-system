'use client';

import { useMemo, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  evaluateUploadSubjectReadiness,
  filterDepartmentsByUploadScope,
  getMinRetentionDate,
  isClassificationAllowedForClearance,
  resolveUploadWizardDefaults,
  validateDocumentCodeInput,
  validateRetentionDateInput,
  validateUploadFileInput,
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
  hasGlobalDocumentUpload?: boolean | undefined;
  documentUploadDepartmentIds?: readonly (string | number)[] | undefined;
  canCreateVersion?: boolean | undefined;
  canClassify?: boolean | undefined;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  classificationLevels: ClassificationLevelLookupItem[];
  ensureUploadLookups?: () => Promise<void>;
  refreshData: (options?: { silent?: boolean; scope?: OwnerTab }) => Promise<void>;
  setMessage: (msg: string | null) => void;
  setDialogError: (msg: string | null) => void;
}

/**
 * Thuật toán: Quy Trình Tải Lên Tài Liệu 3 Bước Có Kiểm Định Tệp 50MB, Đuôi Kép, Mã Tài Liệu & Phạm Vi Phòng Ban (`useUploadWizard`, BUG-102, BUG-103, BUG-120)
 * Mục đích:
 *   - Chặn ngay tại Bước 1 tệp rỗng, tệp vượt 50MB, phần mở rộng thực thi ngụy trang (`.pdf.exe`, `.docx.bat`, `.js`, `.ps1`...) và `docCode` sai biểu thức chính quy.
 *   - Lọc danh sách phòng ban chủ quản theo đúng cây con phòng ban được cấp quyền tải lên của chủ thể.
 *   - Khóa đóng hộp thoại khi đang truyền tải tệp lên máy chủ (`isSubmittingDoc`).
 */
export function useUploadWizard({
  userDepartmentId,
  userClearanceRank,
  userStatus,
  hasGlobalDocumentUpload,
  documentUploadDepartmentIds,
  canCreateVersion = true,
  canClassify = true,
  departments,
  businessCategories,
  classificationLevels,
  ensureUploadLookups,
  refreshData,
  setMessage,
  setDialogError,
}: UseUploadWizardParams) {
  const [uploadWizardOpen, setUploadWizardOpenState] = useState(false);
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

  const permittedDepartments = useMemo(
    () =>
      filterDepartmentsByUploadScope({
        departments,
        userDepartmentId,
        hasGlobalUploadScope: hasGlobalDocumentUpload,
        uploadDepartmentIds: documentUploadDepartmentIds,
      }),
    [departments, documentUploadDepartmentIds, hasGlobalDocumentUpload, userDepartmentId],
  );

  const wizardDefaults = resolveUploadWizardDefaults({
    userDepartmentId,
    userClearanceRank,
    departments: permittedDepartments,
    businessCategories,
    classificationLevels,
  });

  const effectiveDepartmentId = useMemo(() => {
    if (
      docDepartmentOverride !== null &&
      (permittedDepartments.length === 0 ||
        permittedDepartments.some((d) => Number(d.id) === docDepartmentOverride))
    ) {
      return docDepartmentOverride;
    }
    return wizardDefaults.departmentId;
  }, [docDepartmentOverride, permittedDepartments, wizardDefaults.departmentId]);

  const docCategoryId = docCategoryOverride ?? wizardDefaults.categoryId;
  const docClassificationId = docClassificationOverride ?? wizardDefaults.classificationId;

  const setDocDepartmentId = (value: number) => setDocDepartmentOverride(value);
  const setDocCategoryId = (value: number) => setDocCategoryOverride(value);
  const setDocClassificationId = (value: number) => setDocClassificationOverride(value);

  const minRetentionDate = getMinRetentionDate();
  const retentionDateError = validateRetentionDateInput(docRetentionDate);
  const fileValidationError = docFile ? validateUploadFileInput(docFile) : null;
  const docCodeError = validateDocumentCodeInput(docCode);
  const subjectReadiness = evaluateUploadSubjectReadiness({
    departmentId: userDepartmentId,
    clearanceRank: userClearanceRank,
    status: userStatus,
  });

  function setUploadWizardOpen(nextOpen: boolean) {
    if (!nextOpen && isSubmittingDoc) return;
    if (!nextOpen) {
      setDialogError(null);
    }
    setUploadWizardOpenState(nextOpen);
  }

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

  function validateStepOne(): string | null {
    const fileErr = validateUploadFileInput(docFile);
    if (fileErr) return fileErr;
    if (!docTitle.trim()) {
      return 'Tiêu đề tài liệu không được để trống.';
    }
    const codeErr = validateDocumentCodeInput(docCode);
    if (codeErr) return codeErr;
    if (
      permittedDepartments.length > 0 &&
      !permittedDepartments.some((d) => Number(d.id) === Number(effectiveDepartmentId))
    ) {
      return 'Phòng ban chủ quản đã chọn nằm ngoài phạm vi tải lên được cấp quyền của bạn.';
    }
    return resolveClearanceError();
  }

  function handleNextStep() {
    if (wizardStep === 1) {
      const stepOneErr = validateStepOne();
      if (stepOneErr) {
        setDialogError(stepOneErr);
        return;
      }
      setDialogError(null);
      setWizardStep(2);
      return;
    }

    if (wizardStep === 2) {
      const retentionErr = validateRetentionDateInput(docRetentionDate);
      if (retentionErr) {
        setDialogError(retentionErr);
        return;
      }
      setDialogError(null);
      setWizardStep(3);
    }
  }

  function openUploadWizard() {
    setDialogError(null);
    void ensureUploadLookups?.();
    if (!docFile && !docTitle.trim()) {
      setDocDepartmentOverride(null);
      setDocCategoryOverride(null);
      setDocClassificationOverride(null);
    }
    setWizardStep(1);
    setUploadWizardOpenState(true);
  }

  async function handleFinishUpload() {
    const stepOneErr = validateStepOne();
    if (stepOneErr || !docFile) {
      setDialogError(stepOneErr || 'Vui lòng chọn tệp tài liệu trước khi tiếp tục.');
      setWizardStep(1);
      return;
    }

    const retentionErr = validateRetentionDateInput(docRetentionDate);
    if (retentionErr) {
      setDialogError(retentionErr);
      setWizardStep(2);
      return;
    }

    setIsSubmittingDoc(true);
    setDialogError(null);

    try {
      const formData = new FormData();
      formData.append('title', docTitle.trim());
      if (docCode.trim()) {
        formData.append('documentCode', docCode.trim());
      }
      formData.append('departmentId', String(effectiveDepartmentId));
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

      if (canCreateVersion) {
        try {
          await apiClient(`/documents/${docId}/current-version`, {
            method: 'POST',
            body: JSON.stringify({ versionNo: uploadRes.versionNo ?? 1 }),
          });
        } catch (verErr) {
          console.warn('Could not explicitly set current-version:', verErr);
        }
      }

      let activated = false;
      if (canClassify) {
        try {
          await apiClient(`/documents/${docId}/activate`, {
            method: 'POST',
          });
          activated = true;
        } catch (actErr) {
          console.warn('Could not automatically activate document, leaving as DRAFT:', actErr);
        }
      }

      const selectedLevel = classificationLevels.find(
        (l) => String(l.id) === String(docClassificationId),
      );
      const levelName = selectedLevel?.name ?? 'Mật';
      const uploadedTitle = docTitle.trim();
      const uploadedFilename = docFile.name;

      setIsSubmittingDoc(false);
      setUploadWizardOpenState(false);
      setWizardStep(1);
      setDocFile(null);
      setDocTitle('');
      setDocCode('');
      setDocDescription('');
      setDocRetentionDate('');
      setDocDepartmentOverride(null);
      setDocCategoryOverride(null);
      setDocClassificationOverride(null);
      setMessage(
        activated
          ? `Tài liệu "${uploadedTitle}" (${uploadedFilename}) đã được tải lên và kích hoạt thành công với mức độ mật ${levelName}.`
          : `Tài liệu "${uploadedTitle}" (${uploadedFilename}) đã được tải lên ở trạng thái bản nháp (mức độ mật ${levelName}). Bạn có thể kích hoạt thủ công trong danh sách.`,
      );
      await refreshData({ silent: true, scope: 'documents' });
    } catch (err) {
      if (err instanceof ApiError) {
        setDialogError(err.message || 'Không thể tải lên tài liệu mới.');
      } else {
        setDialogError('Đã xảy ra lỗi trong quá trình tải lên tài liệu.');
      }
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
    docDepartmentId: effectiveDepartmentId,
    setDocDepartmentId,
    docCategoryId,
    setDocCategoryId,
    docClassificationId,
    setDocClassificationId,
    docRetentionDate,
    setDocRetentionDate,
    permittedDepartments,
    fileValidationError,
    docCodeError,
    minRetentionDate,
    retentionDateError,
    subjectReadiness,
    isSubmittingDoc,
    openUploadWizard,
    handleNextStep,
    handleFinishUpload,
  };
}
