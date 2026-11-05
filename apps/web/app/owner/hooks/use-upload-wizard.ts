'use client';

import { useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { resolveUploadWizardDefaults } from '../helpers';
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
 * Thuật toán: Quy trình Tải lên Tài liệu 3 Bước Bắt buộc Gắn Nhãn Mật (`useUploadWizard`)
 * Khởi tạo phòng ban/danh mục/mức mật mặc định từ danh mục tra cứu thực, tải lên multipart, gắn phiên bản hiện hành và kích hoạt tài liệu `ACTIVE`.
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
    // CONFLICT-RESOLVED: Khắc phục điều kiện chết (!docDepartmentId / !docCategoryId / !docClassificationId khi state ban đầu là 1, 1, 3) để luôn khởi tạo đúng mặc định khi mở trình tải lên mới.
    if (!docFile && !docTitle.trim()) {
      const defaults = resolveUploadWizardDefaults({
        userDepartmentId,
        departments,
        businessCategories,
        classificationLevels,
      });
      setDocDepartmentId(defaults.departmentId);
      setDocCategoryId(defaults.categoryId);
      setDocClassificationId(defaults.classificationId);
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
