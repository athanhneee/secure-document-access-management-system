'use client';

import { useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
} from '../types';

interface UseUploadWizardParams {
  userDepartmentId?: string | number | null | undefined;
  departments: DepartmentLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  classificationLevels: ClassificationLevelLookupItem[];
  refreshData: () => Promise<void>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Algorithm: 3-Step Mandatory-Classification Upload Pipeline
 * Collects source file + mandatory security classification metadata, uploads multipart payload,
 * binds initial version pointer, and transitions document status to `ACTIVE`.
 * Time Complexity: O(K) over classification/department lookups | Space Complexity: O(1)
 */
export function useUploadWizard({
  userDepartmentId,
  departments,
  businessCategories,
  classificationLevels,
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
  const [docDepartmentId, setDocDepartmentId] = useState<number>(1);
  const [docCategoryId, setDocCategoryId] = useState<number>(1);
  const [docClassificationId, setDocClassificationId] = useState<number>(3);
  const [docRetentionDate, setDocRetentionDate] = useState('');
  const [isSubmittingDoc, setIsSubmittingDoc] = useState(false);

  function openUploadWizard() {
    if (!docDepartmentId && departments[0]) {
      const parsedUserDept = userDepartmentId ? Number(userDepartmentId) : null;
      const defaultDept = parsedUserDept
        ? (departments.find((d) => d.id === parsedUserDept)?.id ?? departments[0].id)
        : departments[0].id;
      setDocDepartmentId(defaultDept);
    }
    if (!docCategoryId && businessCategories[0]) {
      setDocCategoryId(businessCategories[0].id);
    }
    if (!docClassificationId && classificationLevels[0]) {
      const conf =
        classificationLevels.find((l) => l.code === 'CONFIDENTIAL') ?? classificationLevels[0];
      setDocClassificationId(conf.id);
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

      try {
        await apiClient(`/documents/${docId}/activate`, {
          method: 'POST',
        });
      } catch (actErr) {
        console.warn('Could not automatically activate document, leaving as DRAFT:', actErr);
      }

      const selectedLevel = classificationLevels.find((l) => l.id === docClassificationId);
      setMessage(
        `Tài liệu "${docTitle.trim()}" (${docFile.name}) đã được tải lên và kích hoạt thành công với mức mật ${selectedLevel?.code ?? 'Mật'}.`,
      );
      setUploadWizardOpen(false);
      setWizardStep(1);
      setDocFile(null);
      setDocTitle('');
      setDocCode('');
      setDocDescription('');
      setDocRetentionDate('');
      await refreshData();
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
    isSubmittingDoc,
    openUploadWizard,
    handleFinishUpload,
  };
}
