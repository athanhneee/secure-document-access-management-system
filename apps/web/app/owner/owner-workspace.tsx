'use client';

import { useState, useEffect, useCallback, type FormEvent } from 'react';
import {
  FileUp,
  FolderLock,
  Clock,
  KeyRound,
  History,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Check,
  X,
  ShieldCheck,
  AlertOctagon,
  Eye,
  Download,
  ChevronLeft,
  ChevronRight,
  QrCode,
  FileType,
  Plus,
  Layers,
  Archive,
  Info,
} from 'lucide-react';
import { apiClient, apiDownload, ApiError, verifyPdfMagicBytes } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { ClassificationBadge, type ClassificationCode } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

// ── Types ───────────────────────────────────────────────────────────────────

interface DocumentItem {
  id: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  classificationRank?: number | undefined;
  classificationLevelId?: number | undefined;
  businessCategoryId?: number | undefined;
  businessCategoryName?: string | undefined;
  status: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  departmentId?: number | undefined;
  departmentName?: string | undefined;
  allowDownload: boolean;
  versionCount?: number | undefined;
  createdAt: string;
}

interface DocumentApiDto {
  id: string;
  title?: string;
  documentCode?: string;
  document_code?: string;
  classificationCode?: ClassificationCode;
  classification?: {
    id?: number;
    code?: ClassificationCode;
    rank?: number;
    allowDownload?: boolean;
  };
  classification_level_id?: number;
  business_category_id?: number;
  businessCategory?: { id?: number; name?: string };
  business_categories?: { id?: number; name?: string };
  status?: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  department_id?: number;
  department?: { id?: number; name?: string };
  departments?: { id?: number; name?: string };
  allowDownload?: boolean;
  versions?: unknown[];
  createdAt?: string;
  created_at?: string;
}

interface AccessGrantApiDto {
  id: string;
  documentId: string;
  document?: { title?: string };
  principalType?: 'USER' | 'ROLE';
  principalUser?: { fullName?: string };
  principalRole?: { name?: string };
  permissions?: string[];
  validFrom?: string;
  validUntil?: string;
  status?: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  version?: number;
}

interface AccessRequestItem {
  id: string;
  documentId: string;
  documentTitle: string;
  requestorName: string;
  requestorDepartment: string;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  requestedFrom?: string;
  requestedUntil?: string;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  createdAt: string;
}

interface AccessGrantItem {
  id: string;
  documentId: string;
  documentTitle: string;
  principalType: 'USER' | 'ROLE';
  principalName: string;
  permissions: string[];
  validFrom: string;
  validUntil: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  version: number;
}

interface DepartmentLookupItem {
  id: number;
  code: string;
  name: string;
}

interface BusinessCategoryLookupItem {
  id: number;
  code: string;
  name: string;
  departmentId: number | null;
}

interface ClassificationLevelLookupItem {
  id: number;
  code: ClassificationCode;
  name: string;
  rank: number;
  allowDownload: boolean;
  requireWatermark: boolean;
  defaultViewDays?: number;
}

interface UserLookupItem {
  id: string;
  username: string;
  fullName: string;
  departmentName: string;
  clearanceRank: number;
}

interface RoleLookupItem {
  id: string;
  code: string;
  name: string;
}

interface AuditLogItem {
  id: string;
  occurredAt: string;
  actorUserId: string | null;
  actorUsername: string | null;
  action: string;
  objectType: string;
  objectId: string | null;
  documentId: string | null;
  accessSessionId: string | null;
  outcome: string;
  reasonCode: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  details: Record<string, unknown> | null;
  entryHash: string;
  chainSequence: string;
}

interface DocumentVersionItem {
  id: string;
  versionNo: number;
  originalFilename: string;
  mimeType: string;
  fileSizeBytes: string;
  sha256Hash: string;
  scanStatus: string;
  changeNote: string | null;
  uploadedBy: string;
  createdAt: string;
}

interface ClassificationHistoryItem {
  id: string;
  classificationLevelCode: string;
  classificationLevelName: string;
  rank: number;
  businessCategoryCode: string;
  businessCategoryName: string;
  reason: string | null;
  classifiedBy: string;
  effectiveFrom: string;
  effectiveTo: string | null;
}

function toLocalISO(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function OwnerWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('documents');
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);

  // Lookups state
  const [departments, setDepartments] = useState<DepartmentLookupItem[]>([]);
  const [businessCategories, setBusinessCategories] = useState<BusinessCategoryLookupItem[]>([]);
  const [classificationLevels, setClassificationLevels] = useState<ClassificationLevelLookupItem[]>(
    [],
  );
  const [usersLookup, setUsersLookup] = useState<UserLookupItem[]>([]);
  const [rolesLookup, setRolesLookup] = useState<RoleLookupItem[]>([]);

  // Audit Logs state
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotalPages, setAuditTotalPages] = useState(1);
  const [auditTotal, setAuditTotal] = useState(0);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLogItem | null>(null);
  const [auditDetailOpen, setAuditDetailOpen] = useState(false);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Preview and Download States
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<DocumentItem | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewPdfUrl, setPreviewPdfUrl] = useState<string | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);

  // 3-step Upload Wizard State
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

  // Direct Access Grant Modal State
  const [directGrantOpen, setDirectGrantOpen] = useState(false);
  const [directDocId, setDirectDocId] = useState('');
  const [directPrincipalType, setDirectPrincipalType] = useState<'USER' | 'ROLE'>('USER');
  const [directUserId, setDirectUserId] = useState('');
  const [directRoleId, setDirectRoleId] = useState('');
  const [directPermissions, setDirectPermissions] = useState<('VIEW' | 'DOWNLOAD')[]>(['VIEW']);
  const [directValidFrom, setDirectValidFrom] = useState(() => toLocalISO(new Date()));
  const [directValidUntil, setDirectValidUntil] = useState(() =>
    toLocalISO(new Date(Date.now() + 7 * 86400000)),
  );
  const [isSubmittingDirectGrant, setIsSubmittingDirectGrant] = useState(false);

  // Revoke Grant Modal State
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [selectedGrant, setSelectedGrant] = useState<AccessGrantItem | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);

  // Approve Request Modal State
  const [approveOpen, setApproveOpen] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<AccessRequestItem | null>(null);
  const [grantValidDays, setGrantValidDays] = useState(7);
  const [grantAction, setGrantAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [isApproving, setIsApproving] = useState(false);

  // Lifecycle Modals: Reclassify
  const [reclassifyOpen, setReclassifyOpen] = useState(false);
  const [docForReclassify, setDocForReclassify] = useState<DocumentItem | null>(null);
  const [reclassLevelId, setReclassLevelId] = useState<number>(1);
  const [reclassCategoryId, setReclassCategoryId] = useState<number>(1);
  const [reclassReason, setReclassReason] = useState('');
  const [isReclassifying, setIsReclassifying] = useState(false);

  // Lifecycle Modals: New Version Upload
  const [newVersionOpen, setNewVersionOpen] = useState(false);
  const [docForNewVersion, setDocForNewVersion] = useState<DocumentItem | null>(null);
  const [newVersionFile, setNewVersionFile] = useState<File | null>(null);
  const [newVersionNote, setNewVersionNote] = useState('');
  const [isUploadingVersion, setIsUploadingVersion] = useState(false);

  // Lifecycle Modals: Archive
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [docForArchive, setDocForArchive] = useState<DocumentItem | null>(null);
  const [archiveReason, setArchiveReason] = useState('');
  const [isArchiving, setIsArchiving] = useState(false);

  // Lifecycle Modals: Version History
  const [versionHistoryOpen, setVersionHistoryOpen] = useState(false);
  const [docVersions, setDocVersions] = useState<DocumentVersionItem[]>([]);
  const [isLoadingVersions, setIsLoadingVersions] = useState(false);
  const [docForVersions, setDocForVersions] = useState<DocumentItem | null>(null);

  // Lifecycle Modals: Classification History
  const [classHistoryOpen, setClassHistoryOpen] = useState(false);
  const [docClassHistory, setDocClassHistory] = useState<ClassificationHistoryItem[]>([]);
  const [isLoadingClassHistory, setIsLoadingClassHistory] = useState(false);
  const [docForClassHistory, setDocForClassHistory] = useState<DocumentItem | null>(null);

  // Load Audit Logs function
  const loadAuditLogs = useCallback(async (page = 1) => {
    setIsLoadingAudit(true);
    try {
      const res = await apiClient<{
        data: AuditLogItem[];
        total: number;
        page: number;
        pageSize: number;
        totalPages: number;
      }>(`/audit-logs?page=${page}&pageSize=15`);
      setAuditLogs(res.data || []);
      setAuditPage(res.page || 1);
      setAuditTotalPages(res.totalPages || 1);
      setAuditTotal(res.total || 0);
    } catch {
      // Do not invent fake audit data if call fails
      setAuditLogs([]);
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const [
      docsResult,
      grantsResult,
      requestsResult,
      deptsResult,
      catsResult,
      levelsResult,
      usersResult,
      rolesResult,
    ] = await Promise.allSettled([
      apiClient<{ data: DocumentApiDto[] }>('/documents?pageSize=50'),
      apiClient<{ data: AccessGrantApiDto[] }>('/access-grants?pageSize=50'),
      apiClient<{ data: AccessRequestItem[] }>('/access-requests?scope=incoming&status=PENDING'),
      apiClient<{ data: DepartmentLookupItem[] }>('/departments/lookup'),
      apiClient<{ data: BusinessCategoryLookupItem[] }>('/classifications/categories'),
      apiClient<{ data: ClassificationLevelLookupItem[] }>('/classifications/levels'),
      apiClient<{ data: UserLookupItem[] }>('/users/lookup'),
      apiClient<{ data: RoleLookupItem[] }>('/rbac/roles/lookup'),
    ]);

    // Handle Documents
    if (docsResult.status === 'fulfilled') {
      const mappedDocs: DocumentItem[] = (docsResult.value.data || []).map((d) => {
        const clsCode = (d.classification?.code ||
          d.classificationCode ||
          'CONFIDENTIAL') as ClassificationCode;
        const clsRank = d.classification?.rank ?? 3;
        const clsAllowDownload = d.classification?.allowDownload ?? clsRank <= 2;
        const deptName = d.department?.name || d.departments?.name;
        const catName = d.businessCategory?.name || d.business_categories?.name;
        return {
          id: d.id,
          title: d.title || 'Tài liệu không tên',
          documentCode: d.documentCode || d.document_code,
          classificationCode: clsCode,
          classificationRank: clsRank,
          classificationLevelId: d.classification?.id ?? d.classification_level_id,
          businessCategoryId: d.business_category_id,
          businessCategoryName: catName,
          status: d.status || 'ACTIVE',
          departmentId: d.department_id,
          departmentName: deptName,
          allowDownload: d.allowDownload ?? clsAllowDownload,
          versionCount: d.versions?.length ?? 1,
          createdAt: d.createdAt || d.created_at || new Date().toISOString(),
        };
      });
      setDocuments(mappedDocs);
    } else {
      setErrorMessage('Không thể tải danh sách tài liệu từ máy chủ.');
    }

    // Handle Grants
    if (grantsResult.status === 'fulfilled') {
      const mappedGrants: AccessGrantItem[] = (grantsResult.value.data || []).map((g) => ({
        id: g.id,
        documentId: g.documentId,
        documentTitle: g.document?.title || 'Tài liệu ' + g.documentId.slice(0, 8),
        principalType: g.principalType || 'USER',
        principalName: g.principalUser?.fullName || g.principalRole?.name || 'Đối tượng được cấp',
        permissions: g.permissions || ['VIEW'],
        validFrom: g.validFrom || new Date().toISOString(),
        validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
        status: g.status || 'ACTIVE',
        version: g.version || 0,
      }));
      setGrants(mappedGrants);
    }

    // Handle Requests
    if (requestsResult.status === 'fulfilled') {
      setRequests(requestsResult.value.data || []);
    }

    // Handle Departments Lookup
    if (deptsResult.status === 'fulfilled') {
      const depts = deptsResult.value.data || [];
      setDepartments(depts);
      if (depts.length > 0 && !docDepartmentId && depts[0]) {
        const userDeptId = user?.departmentId ? Number(user.departmentId) : null;
        const defaultDept = userDeptId
          ? (depts.find((d) => d.id === userDeptId)?.id ?? depts[0].id)
          : depts[0].id;
        setDocDepartmentId(defaultDept);
      }
    }

    // Handle Categories Lookup
    if (catsResult.status === 'fulfilled') {
      const cats = catsResult.value.data || [];
      setBusinessCategories(cats);
      if (cats.length > 0 && !docCategoryId && cats[0]) {
        setDocCategoryId(cats[0].id);
      }
    }

    // Handle Classification Levels Lookup
    if (levelsResult.status === 'fulfilled') {
      const levels = levelsResult.value.data || [];
      setClassificationLevels(levels);
      if (levels.length > 0 && !docClassificationId && levels[0]) {
        const conf = levels.find((l) => l.code === 'CONFIDENTIAL') ?? levels[0];
        setDocClassificationId(conf.id);
      }
    }

    // Handle Users Lookup
    if (usersResult.status === 'fulfilled') {
      setUsersLookup(usersResult.value.data || []);
    }

    // Handle Roles Lookup
    if (rolesResult.status === 'fulfilled') {
      setRolesLookup(rolesResult.value.data || []);
    }

    setIsLoading(false);
  }, [user, docDepartmentId, docCategoryId, docClassificationId]);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshData();
        void loadAuditLogs(1);
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refreshData, loadAuditLogs]);

  const handleClosePreview = useCallback(
    (open: boolean) => {
      setPreviewOpen(open);
      if (!open && previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
        setPreviewPdfUrl(null);
      }
    },
    [previewPdfUrl],
  );

  // Open Preview with Controlled Session
  async function handleOpenPreview(doc: DocumentItem) {
    setIsLoadingPreview(true);
    setErrorMessage(null);
    if (previewPdfUrl) {
      URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(null);
    }

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      setPreviewDoc(doc);
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewPage(1);
      setPreviewOpen(true);

      // Fetch the watermarked PDF preview stream directly from backend
      try {
        const pdfBlob = await apiDownload(
          `/documents/${doc.id}/preview?sessionId=${sessionResult.sessionId}`,
        );
        if (!(await verifyPdfMagicBytes(pdfBlob))) {
          throw new Error('Invalid PDF stream header.');
        }
        if (pdfBlob.totalPages && pdfBlob.totalPages > 0) {
          setPreviewTotalPages(pdfBlob.totalPages);
        } else {
          setPreviewTotalPages(1);
        }
        const objectUrl = URL.createObjectURL(pdfBlob);
        setPreviewPdfUrl(objectUrl);
      } catch (streamErr) {
        console.warn('Could not load binary PDF preview stream:', streamErr);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo phiên xem trước tài liệu.');
      } else {
        setErrorMessage('Không thể tạo phiên xem trước tài liệu.');
      }
    } finally {
      setIsLoadingPreview(false);
    }
  }

  // Handle Page Change in Preview
  async function handlePageChange(newPage: number) {
    if (!previewDoc || !previewSessionId || newPage === previewPage) return;
    setIsLoadingPreview(true);
    try {
      const pageBlob = await apiDownload(
        `/documents/${previewDoc.id}/preview/page/${newPage}?sessionId=${previewSessionId}`,
      );
      if (!(await verifyPdfMagicBytes(pageBlob))) {
        throw new Error('Invalid PDF stream header.');
      }
      if (previewPdfUrl) {
        URL.revokeObjectURL(previewPdfUrl);
      }
      setPreviewPdfUrl(URL.createObjectURL(pageBlob));
      setPreviewPage(newPage);
    } catch (err) {
      console.error('Could not load page preview:', err);
    } finally {
      setIsLoadingPreview(false);
    }
  }

  // Handle Download Ticket Flow
  async function handleDownloadWithTicket(doc: DocumentItem) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này thuộc diện cấm tải theo chính sách phân loại mật.');
      return;
    }

    setDownloadingDocId(doc.id);
    setErrorMessage(null);

    try {
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.id}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'DOWNLOAD' }),
        },
      );

      const ticketResult = await apiClient<{ ticket: string; expiresAt: string }>(
        `/documents/${doc.id}/download-ticket`,
        {
          method: 'POST',
          body: JSON.stringify({ sessionId: sessionResult.sessionId }),
        },
      );

      const blob = await apiDownload(`/documents/download-with-ticket/${ticketResult.ticket}`);

      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `${doc.documentCode || 'DOCUMENT'}_watermarked.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);

      setMessage(`Đã tạo và tải bản sao tài liệu có dấu bản quyền thành công.`);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo bản sao tải về.');
      }
    } finally {
      setDownloadingDocId(null);
    }
  }

  // Handle Upload Document Flow
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

      // Set current-version and activate
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

  // Handle Direct Access Grant Creation
  async function handleCreateDirectGrant(e: FormEvent) {
    e.preventDefault();
    if (!directDocId) {
      setErrorMessage('Vui lòng chọn tài liệu cần cấp quyền.');
      return;
    }
    if (directPrincipalType === 'USER' && !directUserId) {
      setErrorMessage('Vui lòng chọn người dùng được cấp quyền.');
      return;
    }
    if (directPrincipalType === 'ROLE' && !directRoleId) {
      setErrorMessage('Vui lòng chọn vai trò được cấp quyền.');
      return;
    }
    if (directPermissions.length === 0) {
      setErrorMessage('Vui lòng chọn ít nhất một quyền (VIEW hoặc DOWNLOAD).');
      return;
    }
    if (!directValidFrom || !directValidUntil) {
      setErrorMessage('Vui lòng nhập đầy đủ thời gian bắt đầu và kết thúc hiệu lực.');
      return;
    }
    if (new Date(directValidUntil) <= new Date(directValidFrom)) {
      setErrorMessage('Thời gian kết thúc phải diễn ra sau thời gian bắt đầu.');
      return;
    }

    setIsSubmittingDirectGrant(true);
    setErrorMessage(null);

    try {
      const payload: {
        documentId: string;
        principalType: 'USER' | 'ROLE';
        principalUserId?: string;
        principalRoleId?: string;
        permissions: ('VIEW' | 'DOWNLOAD')[];
        validFrom: string;
        validUntil: string;
      } = {
        documentId: directDocId,
        principalType: directPrincipalType,
        permissions: directPermissions,
        validFrom: new Date(directValidFrom).toISOString(),
        validUntil: new Date(directValidUntil).toISOString(),
      };

      if (directPrincipalType === 'USER') {
        payload.principalUserId = directUserId;
      } else {
        payload.principalRoleId = directRoleId;
      }

      await apiClient('/access-grants', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      setMessage('Đã cấp giấy phép truy cập trực tiếp thành công.');
      setDirectGrantOpen(false);
      setDirectDocId('');
      setDirectUserId('');
      setDirectRoleId('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cấp quyền truy cập.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo giấy phép truy cập.');
      }
    } finally {
      setIsSubmittingDirectGrant(false);
    }
  }

  // Handle Activate Draft Document
  async function handleActivateDocument(doc: DocumentItem) {
    setErrorMessage(null);
    try {
      await apiClient(`/documents/${doc.id}/activate`, {
        method: 'POST',
      });
      setMessage(`Đã kích hoạt tài liệu "${doc.title}" thành công.`);
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể kích hoạt tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi kích hoạt tài liệu.');
      }
    }
  }

  // Handle Revoke Grant
  async function handleConfirmRevoke(e: FormEvent) {
    e.preventDefault();
    if (!selectedGrant) return;

    if (revokeReason.trim().length < 10) {
      setErrorMessage('Lý do thu hồi bắt buộc phải có ít nhất 10 ký tự để ghi nhật ký kiểm toán.');
      return;
    }

    setIsRevoking(true);
    setErrorMessage(null);
    try {
      await apiClient(`/access-grants/${selectedGrant.id}/revoke`, {
        method: 'POST',
        body: JSON.stringify({
          reason: revokeReason.trim(),
          expectedVersion: selectedGrant.version,
        }),
      });

      setMessage(
        `Đã thu hồi quyền truy cập của ${selectedGrant.principalName}. Mọi phiên làm việc đang chạy đã bị chấm dứt tức thì.`,
      );
      setRevokeOpen(false);
      setSelectedGrant(null);
      setRevokeReason('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể thu hồi quyền.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi thu hồi quyền truy cập.');
      }
    } finally {
      setIsRevoking(false);
    }
  }

  // Handle Approve Request
  async function handleConfirmApprove() {
    if (!selectedRequest) return;
    setIsApproving(true);
    setErrorMessage(null);

    try {
      await apiClient(`/access-requests/${selectedRequest.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'APPROVED',
          validDays: grantValidDays,
          permissions: [grantAction],
        }),
      });

      setMessage(
        `Đã phê duyệt yêu cầu và cấp quyền ${grantAction} tài liệu cho ${selectedRequest.requestorName} trong ${grantValidDays} ngày.`,
      );
      setApproveOpen(false);
      setSelectedRequest(null);
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể phê duyệt yêu cầu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo giấy phép truy cập.');
      }
    } finally {
      setIsApproving(false);
    }
  }

  // Handle Reject Request
  async function handleRejectRequest(req: AccessRequestItem) {
    setErrorMessage(null);
    try {
      await apiClient(`/access-requests/${req.id}/decide`, {
        method: 'POST',
        body: JSON.stringify({
          decision: 'REJECTED',
          decisionNote: 'Chủ sở hữu từ chối cấp quyền truy cập.',
        }),
      });
      setMessage(`Đã từ chối yêu cầu truy cập của ${req.requestorName}.`);
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể từ chối yêu cầu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi từ chối yêu cầu.');
      }
    }
  }

  // Handle Reclassify Document
  async function handleConfirmReclassify(e: FormEvent) {
    e.preventDefault();
    if (!docForReclassify) return;
    if (!reclassReason.trim()) {
      setErrorMessage('Vui lòng nhập lý do điều chỉnh phân loại mật.');
      return;
    }

    setIsReclassifying(true);
    setErrorMessage(null);
    try {
      await apiClient(`/documents/${docForReclassify.id}/classify`, {
        method: 'POST',
        body: JSON.stringify({
          classificationLevelId: String(reclassLevelId),
          businessCategoryId: String(reclassCategoryId),
          reason: reclassReason.trim(),
        }),
      });

      setMessage(`Đã điều chỉnh phân loại tài liệu "${docForReclassify.title}" thành công.`);
      setReclassifyOpen(false);
      setDocForReclassify(null);
      setReclassReason('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể điều chỉnh phân loại tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi điều chỉnh phân loại.');
      }
    } finally {
      setIsReclassifying(false);
    }
  }

  // Handle Upload New Version
  async function handleConfirmNewVersion(e: FormEvent) {
    e.preventDefault();
    if (!docForNewVersion || !newVersionFile) {
      setErrorMessage('Vui lòng chọn tệp phiên bản mới.');
      return;
    }

    setIsUploadingVersion(true);
    setErrorMessage(null);
    try {
      const formData = new FormData();
      formData.append('documentId', docForNewVersion.id);
      formData.append('file', newVersionFile);
      if (newVersionNote.trim()) {
        formData.append('changeNote', newVersionNote.trim());
      }

      const res = await apiClient<{ versionNo: number }>('/documents/upload', {
        method: 'POST',
        body: formData,
      });

      // Update current version
      try {
        await apiClient(`/documents/${docForNewVersion.id}/current-version`, {
          method: 'POST',
          body: JSON.stringify({ versionNo: res.versionNo }),
        });
      } catch (vErr) {
        console.warn('Could not auto-set current version:', vErr);
      }

      setMessage(
        `Đã tải lên phiên bản v${res.versionNo}.0 cho tài liệu "${docForNewVersion.title}".`,
      );
      setNewVersionOpen(false);
      setDocForNewVersion(null);
      setNewVersionFile(null);
      setNewVersionNote('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tải lên phiên bản mới.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật phiên bản.');
      }
    } finally {
      setIsUploadingVersion(false);
    }
  }

  // Handle Archive Document
  async function handleConfirmArchive(e: FormEvent) {
    e.preventDefault();
    if (!docForArchive) return;

    setIsArchiving(true);
    setErrorMessage(null);
    try {
      await apiClient(`/documents/${docForArchive.id}/archive`, {
        method: 'POST',
        body: JSON.stringify({
          reason: archiveReason.trim() || 'Lưu trữ tài liệu theo quy chế an toàn',
        }),
      });

      setMessage(
        `Tài liệu "${docForArchive.title}" đã được chuyển vào lưu trữ (ARCHIVED). Mọi phiên đọc đã bị chấm dứt.`,
      );
      setArchiveOpen(false);
      setDocForArchive(null);
      setArchiveReason('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể lưu trữ tài liệu.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi lưu trữ tài liệu.');
      }
    } finally {
      setIsArchiving(false);
    }
  }

  // Handle View Version History
  async function handleOpenVersionHistory(doc: DocumentItem) {
    setDocForVersions(doc);
    setIsLoadingVersions(true);
    setVersionHistoryOpen(true);
    try {
      const res = await apiClient<DocumentVersionItem[] | { data: DocumentVersionItem[] }>(
        `/documents/${doc.id}/versions`,
      );
      const list = Array.isArray(res) ? res : res.data || [];
      setDocVersions(list);
    } catch {
      setDocVersions([]);
    } finally {
      setIsLoadingVersions(false);
    }
  }

  // Handle View Classification History
  async function handleOpenClassHistory(doc: DocumentItem) {
    setDocForClassHistory(doc);
    setIsLoadingClassHistory(true);
    setClassHistoryOpen(true);
    try {
      const res = await apiClient<
        ClassificationHistoryItem[] | { data: ClassificationHistoryItem[] }
      >(`/documents/${doc.id}/classification-history`);
      const list = Array.isArray(res) ? res : res.data || [];
      setDocClassHistory(list);
    } catch {
      setDocClassHistory([]);
    } finally {
      setIsLoadingClassHistory(false);
    }
  }

  const filteredDocs = documents.filter((d) => {
    const q = searchQuery.toLowerCase();
    return (
      d.title.toLowerCase().includes(q) ||
      (d.documentCode && d.documentCode.toLowerCase().includes(q))
    );
  });

  // Selected level in upload wizard
  const currentSelectedLevel = classificationLevels.find((l) => l.id === docClassificationId);

  // Clearance validation for Direct Grant Modal
  const selectedDirectDoc = documents.find((d) => d.id === directDocId);
  const selectedDirectUser = usersLookup.find((u) => u.id === directUserId);
  const isClearanceWarning =
    directPrincipalType === 'USER' &&
    selectedDirectDoc &&
    selectedDirectUser &&
    selectedDirectUser.clearanceRank < (selectedDirectDoc.classificationRank ?? 0);

  return (
    <AuthGuard requiredRole="DOCUMENT_OWNER">
      <AppLayout>
        <div className="space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="warning">Document Owner</Badge>
                <span className="text-xs text-[#717171]">Phân hệ Chủ sở hữu</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Quản lý & Cấp phép Tài liệu Mật
              </h1>
              <p className="text-xs text-[#717171]">
                Tải lên tệp đa phương thức với kiểm tra phân loại bắt buộc, cấp quyền trực tiếp, xét
                duyệt và quản lý toàn diện vòng đời tài liệu
              </p>
            </div>

            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                variant="secondary"
                size="sm"
                text="Làm mới"
                icon={
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`}
                    aria-hidden="true"
                  />
                }
                onClick={() => void refreshData()}
                disabled={isLoading}
              />
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Tải lên tài liệu mới"
                icon={<FileUp size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => {
                  setWizardStep(1);
                  setUploadWizardOpen(true);
                }}
              />
            </div>
          </div>

          {message && (
            <Alert variant="success" className="text-xs">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-[#008A05]" aria-hidden="true" />
              <AlertDescription className="ml-2">{message}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert variant="destructive" className="text-xs">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          {/* Navigation Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger value="documents" className="flex items-center gap-1.5 text-xs">
                <FolderLock className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Tài liệu sở hữu ({documents.length})</span>
              </TabsTrigger>
              <TabsTrigger value="requests" className="flex items-center gap-1.5 text-xs">
                <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  Yêu cầu cần duyệt ({requests.filter((r) => r.status === 'PENDING').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="grants" className="flex items-center gap-1.5 text-xs">
                <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  Giấy phép hiệu lực ({grants.filter((g) => g.status === 'ACTIVE').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="history" className="flex items-center gap-1.5 text-xs">
                <History className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Lịch sử truy cập</span>
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: DOCUMENTS */}
            <TabsContent value="documents" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Kho tài liệu mật đang quản lý
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Mỗi tài liệu bắt buộc gắn nhãn mức mật, phòng ban, danh mục nghiệp vụ và chính
                      sách kiểm soát
                    </CardDescription>
                  </div>
                  <div className="relative w-full sm:w-64">
                    <Search
                      className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#717171]"
                      aria-hidden="true"
                    />
                    <Input
                      type="text"
                      placeholder="Tìm theo tiêu đề, mã số..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-9 h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                    />
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Tên tài liệu / Mã số
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Phòng ban & Danh mục
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                          <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                          <TableHead className="text-xs text-[#717171]">Phiên bản</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Thao tác & Vòng đời
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDocs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={7}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Chưa có tài liệu nào trong danh mục quản lý
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredDocs.map((doc) => (
                            <TableRow
                              key={doc.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-[#222222]">
                                  {doc.title}
                                </div>
                                <div className="text-[11px] font-bold text-[#717171]">
                                  {doc.documentCode || 'DOC-' + doc.id.slice(0, 8)}
                                </div>
                              </TableCell>
                              <TableCell>
                                <div className="text-xs text-[#222222]">
                                  {doc.departmentName || '—'}
                                </div>
                                <div className="text-[11px] text-[#717171]">
                                  {doc.businessCategoryName || 'Nghiệp vụ chung'}
                                </div>
                              </TableCell>
                              <TableCell>
                                <ClassificationBadge level={doc.classificationCode} showRank />
                              </TableCell>
                              <TableCell>
                                {doc.allowDownload ? (
                                  <span className="flex items-center gap-1 text-[11px] text-[#008A05]">
                                    <Download className="h-3 w-3" aria-hidden="true" />
                                    <span>Cho phép tải kèm Watermark</span>
                                  </span>
                                ) : (
                                  <span className="flex items-center gap-1 text-[11px] text-[#E07912]">
                                    <Eye className="h-3 w-3" aria-hidden="true" />
                                    <span>Chỉ xem trực tuyến</span>
                                  </span>
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] font-bold">
                                v{doc.versionCount ?? 1}.0
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={
                                    doc.status === 'ACTIVE'
                                      ? 'success'
                                      : doc.status === 'DRAFT'
                                        ? 'secondary'
                                        : 'destructive'
                                  }
                                >
                                  {doc.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex items-center justify-end gap-1 flex-wrap">
                                  {doc.status === 'DRAFT' && (
                                    <InteractiveHoverButton
                                      variant="primary"
                                      size="sm"
                                      text="Kích hoạt"
                                      icon={<CheckCircle2 size={13} />}
                                      onClick={() => void handleActivateDocument(doc)}
                                    />
                                  )}
                                  <InteractiveHoverButton
                                    variant="secondary"
                                    size="sm"
                                    text="Xem"
                                    icon={<Eye size={13} />}
                                    onClick={() => void handleOpenPreview(doc)}
                                    disabled={isLoadingPreview || doc.status !== 'ACTIVE'}
                                  />
                                  <InteractiveHoverButton
                                    variant={doc.allowDownload ? 'secondary' : 'ghost'}
                                    size="sm"
                                    text="Tải"
                                    icon={<Download size={13} />}
                                    onClick={() => void handleDownloadWithTicket(doc)}
                                    disabled={
                                      !doc.allowDownload ||
                                      downloadingDocId === doc.id ||
                                      doc.status !== 'ACTIVE'
                                    }
                                    isLoading={downloadingDocId === doc.id}
                                  />
                                  {doc.status === 'ACTIVE' && (
                                    <>
                                      <InteractiveHoverButton
                                        variant="secondary"
                                        size="sm"
                                        text="Bản mới"
                                        icon={<Layers size={13} />}
                                        onClick={() => {
                                          setDocForNewVersion(doc);
                                          setNewVersionFile(null);
                                          setNewVersionNote('');
                                          setNewVersionOpen(true);
                                        }}
                                      />
                                      <InteractiveHoverButton
                                        variant="secondary"
                                        size="sm"
                                        text="Đổi mức mật"
                                        icon={<ShieldCheck size={13} />}
                                        onClick={() => {
                                          setDocForReclassify(doc);
                                          setReclassLevelId(doc.classificationLevelId || 1);
                                          setReclassCategoryId(doc.businessCategoryId || 1);
                                          setReclassReason('');
                                          setReclassifyOpen(true);
                                        }}
                                      />
                                      <InteractiveHoverButton
                                        variant="ghost"
                                        size="sm"
                                        text="Lưu trữ"
                                        icon={<Archive size={13} />}
                                        onClick={() => {
                                          setDocForArchive(doc);
                                          setArchiveReason('');
                                          setArchiveOpen(true);
                                        }}
                                      />
                                    </>
                                  )}
                                  <InteractiveHoverButton
                                    variant="ghost"
                                    size="sm"
                                    text="Lịch sử"
                                    icon={<History size={13} />}
                                    onClick={() => void handleOpenVersionHistory(doc)}
                                  />
                                </div>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 2: ACCESS REQUESTS */}
            <TabsContent value="requests" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Hàng đợi yêu cầu cấp quyền
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Xét duyệt yêu cầu đọc hoặc tải tài liệu mật kèm khoảng thời gian sử dụng từ các
                    phòng ban
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Người yêu cầu / Phòng ban
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Tài liệu mục tiêu
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Thời gian yêu cầu
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Lý do nghiệp vụ</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Quyết định
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {requests.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={6}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Không có yêu cầu cấp quyền nào đang chờ duyệt
                            </TableCell>
                          </TableRow>
                        ) : (
                          requests.map((req) => (
                            <TableRow
                              key={req.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-[#222222]">
                                  {req.requestorName}
                                </div>
                                <div className="text-[11px] text-[#717171]">
                                  {req.requestorDepartment}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] max-w-xs truncate">
                                {req.documentTitle}
                              </TableCell>
                              <TableCell>
                                <Badge variant="secondary">{req.requestedAction}</Badge>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222]">
                                {req.requestedFrom && req.requestedUntil ? (
                                  <div>
                                    <div>
                                      {new Date(req.requestedFrom).toLocaleDateString('vi-VN')}
                                    </div>
                                    <div className="text-[#E07912]">
                                      đến {new Date(req.requestedUntil).toLocaleDateString('vi-VN')}
                                    </div>
                                  </div>
                                ) : (
                                  <span className="text-[#717171]">Mặc định 7 ngày</span>
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] max-w-sm">
                                {req.justification}
                              </TableCell>
                              <TableCell className="text-right">
                                {req.status === 'PENDING' ? (
                                  <div className="flex items-center justify-end gap-1.5">
                                    <InteractiveHoverButton
                                      size="sm"
                                      variant="primary"
                                      text="Cấp quyền"
                                      icon={<Check size={14} strokeWidth={2} />}
                                      onClick={() => {
                                        setSelectedRequest(req);
                                        setGrantAction(req.requestedAction);
                                        if (req.requestedFrom && req.requestedUntil) {
                                          const diff = Math.max(
                                            1,
                                            Math.round(
                                              (new Date(req.requestedUntil).getTime() -
                                                new Date(req.requestedFrom).getTime()) /
                                                86400000,
                                            ),
                                          );
                                          setGrantValidDays(diff);
                                        } else {
                                          setGrantValidDays(7);
                                        }
                                        setApproveOpen(true);
                                      }}
                                    />
                                    <InteractiveHoverButton
                                      size="sm"
                                      variant="danger"
                                      text="Từ chối"
                                      icon={<X size={14} strokeWidth={2} />}
                                      onClick={() => void handleRejectRequest(req)}
                                    />
                                  </div>
                                ) : (
                                  <Badge variant="outline" className="text-[10px] text-[#717171]">
                                    {req.status}
                                  </Badge>
                                )}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 3: ACCESS GRANTS */}
            <TabsContent value="grants" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Giấy phép truy cập có thời hạn (Access Grants)
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Cấp trực tiếp cho User hoặc Role; quyền hết hạn hoặc bị thu hồi sẽ chấm dứt
                      mọi phiên đọc lập tức
                    </CardDescription>
                  </div>
                  <InteractiveHoverButton
                    variant="primary"
                    size="sm"
                    text="Cấp quyền trực tiếp"
                    icon={<Plus size={15} strokeWidth={2} />}
                    onClick={() => {
                      if (documents[0] && !directDocId) {
                        setDirectDocId(documents[0].id);
                      }
                      if (usersLookup[0] && !directUserId) {
                        setDirectUserId(usersLookup[0].id);
                      }
                      if (rolesLookup[0] && !directRoleId) {
                        setDirectRoleId(rolesLookup[0].id);
                      }
                      setDirectValidFrom(toLocalISO(new Date()));
                      setDirectValidUntil(toLocalISO(new Date(Date.now() + 7 * 86400000)));
                      setDirectGrantOpen(true);
                    }}
                  />
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Đối tượng được cấp
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                          <TableHead className="text-xs text-[#717171]">Quyền hạn</TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Thời hạn hiệu lực
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Thu hồi khẩn cấp
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {grants.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={6}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Chưa có giấy phép truy cập nào được khởi tạo
                            </TableCell>
                          </TableRow>
                        ) : (
                          grants.map((grant) => (
                            <TableRow
                              key={grant.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-[#222222]">
                                  {grant.principalName}
                                </div>
                                <div className="text-[10px] font-bold text-[#717171]">
                                  {grant.principalType}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] max-w-xs truncate">
                                {grant.documentTitle}
                              </TableCell>
                              <TableCell>
                                <div className="flex gap-1">
                                  {grant.permissions.map((p) => (
                                    <Badge
                                      key={p}
                                      variant="outline"
                                      className="border-[#dddddd] bg-[#f7f7f7] text-[10px] text-[#222222]"
                                    >
                                      {p}
                                    </Badge>
                                  ))}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] font-bold">
                                <div>
                                  Từ: {new Date(grant.validFrom).toLocaleDateString('vi-VN')}
                                </div>
                                <div className="text-[#E07912]">
                                  Đến: {new Date(grant.validUntil).toLocaleDateString('vi-VN')}
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={grant.status === 'ACTIVE' ? 'success' : 'destructive'}
                                  className="text-[10px]"
                                >
                                  {grant.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                {grant.status === 'ACTIVE' && (
                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="danger"
                                    text="Thu hồi"
                                    icon={<AlertOctagon size={14} strokeWidth={2} />}
                                    onClick={() => {
                                      setSelectedGrant(grant);
                                      setRevokeReason('');
                                      setRevokeOpen(true);
                                    }}
                                  />
                                )}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 4: ACCESS HISTORY (AUDIT) */}
            <TabsContent value="history" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Nhật ký truy vết bảo mật (Audit Log)
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Dữ liệu kiểm toán thực từ máy chủ cho các tài liệu thuộc quyền sở hữu của bạn
                    </CardDescription>
                  </div>
                  <InteractiveHoverButton
                    variant="secondary"
                    size="sm"
                    text="Làm mới log"
                    icon={
                      <RefreshCw
                        className={`h-3.5 w-3.5 ${isLoadingAudit ? 'animate-spin' : ''}`}
                      />
                    }
                    onClick={() => void loadAuditLogs(auditPage)}
                    disabled={isLoadingAudit}
                  />
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">Thời điểm</TableHead>
                          <TableHead className="text-xs text-[#717171]">Người thực hiện</TableHead>
                          <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                          <TableHead className="text-xs text-[#717171]">Tài liệu / Phiên</TableHead>
                          <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                          <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Chi tiết
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {isLoadingAudit ? (
                          <TableRow>
                            <TableCell
                              colSpan={7}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-[#FF385C]" />
                              Đang tải dữ liệu kiểm toán...
                            </TableCell>
                          </TableRow>
                        ) : auditLogs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={7}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Chưa có sự kiện kiểm toán nào được ghi nhận cho tài liệu của bạn
                            </TableCell>
                          </TableRow>
                        ) : (
                          auditLogs.map((log) => (
                            <TableRow
                              key={log.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell className="text-xs text-[#222222] whitespace-nowrap">
                                {new Date(log.occurredAt).toLocaleString('vi-VN')}
                              </TableCell>
                              <TableCell>
                                <div className="text-xs font-semibold text-[#222222]">
                                  {log.actorUsername || 'system'}
                                </div>
                                {log.actorUserId && (
                                  <div className="text-[10px] text-[#717171]">
                                    ID: {log.actorUserId}
                                  </div>
                                )}
                              </TableCell>
                              <TableCell>
                                <Badge variant="secondary" className="text-[10px]">
                                  {log.action}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222]">
                                {log.documentId && (
                                  <div className="text-[11px] font-mono text-[#717171]">
                                    Doc: {log.documentId.slice(0, 8)}...
                                  </div>
                                )}
                                {log.accessSessionId && (
                                  <div className="text-[10px] text-[#008489]">
                                    Sess: {log.accessSessionId.slice(0, 12)}
                                  </div>
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-[#717171] font-mono">
                                {log.ipAddress || '—'}
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={log.outcome === 'SUCCESS' ? 'success' : 'destructive'}
                                  className="text-[10px]"
                                >
                                  {log.outcome}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                <InteractiveHoverButton
                                  variant="ghost"
                                  size="sm"
                                  text="Xem"
                                  icon={<Info size={13} />}
                                  onClick={() => {
                                    setSelectedAuditLog(log);
                                    setAuditDetailOpen(true);
                                  }}
                                />
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>

                  {/* Audit Pagination */}
                  <div className="p-3 border-t border-[#ebebeb] flex items-center justify-between text-xs text-[#717171]">
                    <span>Tổng số: {auditTotal} bản ghi</span>
                    <div className="flex items-center gap-2">
                      <InteractiveHoverButton
                        variant="secondary"
                        size="sm"
                        text="Trang trước"
                        icon={<ChevronLeft size={14} />}
                        disabled={auditPage <= 1 || isLoadingAudit}
                        onClick={() => void loadAuditLogs(auditPage - 1)}
                      />
                      <span>
                        Trang {auditPage} / {Math.max(1, auditTotalPages)}
                      </span>
                      <InteractiveHoverButton
                        variant="secondary"
                        size="sm"
                        text="Trang sau"
                        icon={<ChevronRight size={14} />}
                        disabled={auditPage >= auditTotalPages || isLoadingAudit}
                        onClick={() => void loadAuditLogs(auditPage + 1)}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          {/* 3-STEP UPLOAD WIZARD MODAL */}
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
                {wizardStep === 1 && (
                  <div className="space-y-3.5">
                    <div className="space-y-1">
                      <label
                        htmlFor="doc-file-upload"
                        className="text-xs font-medium text-[#222222]"
                      >
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
                          <CheckCircle2 className="h-3.5 w-3.5" />
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
                        <label
                          htmlFor="doc-category"
                          className="text-xs font-medium text-[#222222]"
                        >
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

                    <div className="space-y-2">
                      <span className="block text-xs font-medium text-[#222222]">
                        Mức độ mật bắt buộc (Mandatory Classification){' '}
                        <span className="text-[#C13515]">*</span>
                      </span>
                      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                        {classificationLevels.map((level) => (
                          <button
                            key={level.id}
                            type="button"
                            onClick={() => setDocClassificationId(level.id)}
                            className={`flex flex-col items-center justify-center py-2 px-3 rounded-[40px] border text-center transition-all duration-200 cursor-pointer ${
                              docClassificationId === level.id
                                ? 'border-[#FF385C] bg-[#FF385C]/10 ring-1 ring-[#FF385C]'
                                : 'border-[#ebebeb] bg-[#ffffff] hover:bg-[#f7f7f7] hover:border-[#dddddd]'
                            }`}
                          >
                            <ClassificationBadge level={level.code} size="sm" />
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {wizardStep === 2 && (
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

                    {/* REAL DOWNLOAD POLICY NOTICE DERIVED FROM CLASSIFICATION LEVEL */}
                    <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-[#008489]" />
                        <span className="text-xs font-semibold text-[#222222]">
                          Chính sách tải xuống theo mức mật {currentSelectedLevel?.name}
                        </span>
                      </div>
                      <div className="text-xs text-[#717171] leading-relaxed">
                        {currentSelectedLevel?.allowDownload ? (
                          <div className="text-[#008A05] flex items-center gap-1.5 font-medium">
                            <Download className="h-3.5 w-3.5" />
                            <span>
                              Mức mật này <strong>cho phép tải về</strong> dưới dạng PDF có gắn
                              Watermark động chứa danh tính người tải và mã truy vết QR.
                            </span>
                          </div>
                        ) : (
                          <div className="text-[#E07912] flex items-center gap-1.5 font-medium">
                            <Eye className="h-3.5 w-3.5" />
                            <span>
                              Mức mật này <strong>cấm tải về ngoại tuyến</strong> theo quy chế an
                              toàn dữ liệu. Người dùng chỉ được xem trực tuyến qua Secure Sandbox.
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
                )}

                {wizardStep === 3 && (
                  <div className="space-y-3 text-xs">
                    <div className="rounded-[24px] border border-[#008A05]/20 bg-[#008A05]/5 p-3.5 space-y-2">
                      <div className="flex items-center gap-2 text-[#008A05] font-semibold">
                        <ShieldCheck className="h-4 w-4" />
                        <span>Xác minh trước khi mã hóa lưu trữ</span>
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 text-[#222222] pt-1 border-t border-[#008A05]/15">
                        <span className="text-[#717171]">Tiêu đề:</span>
                        <span className="font-semibold text-[#222222]">{docTitle}</span>
                        <span className="text-[#717171]">Tệp nguồn:</span>
                        <span className="font-bold text-[#222222]">
                          {docFile
                            ? `${docFile.name} (${(docFile.size / 1024).toFixed(1)} KB)`
                            : 'Chưa chọn tệp'}
                        </span>
                        <span className="text-[#717171]">Phòng ban:</span>
                        <span>
                          {departments.find((d) => d.id === docDepartmentId)?.name || 'Chưa chọn'}
                        </span>
                        <span className="text-[#717171]">Danh mục:</span>
                        <span>
                          {businessCategories.find((c) => c.id === docCategoryId)?.name ||
                            'Chưa chọn'}
                        </span>
                        <span className="text-[#717171]">Mức độ mật:</span>
                        <ClassificationBadge
                          level={currentSelectedLevel?.code ?? 'CONFIDENTIAL'}
                          size="sm"
                        />
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
                      Tài liệu sẽ được quét mã độc, trích xuất magic bytes, phân trang an toàn và
                      lưu vào bộ lưu trữ mã hóa độc lập. Dấu bản quyền (Watermark) sẽ được nhúng
                      động mỗi khi có yêu cầu truy cập.
                    </p>
                  </div>
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

          {/* DIRECT ACCESS GRANT MODAL */}
          <Dialog open={directGrantOpen} onOpenChange={setDirectGrantOpen}>
            <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <div className="flex items-center gap-2">
                  <KeyRound className="h-5 w-5 text-[#FF385C]" />
                  <DialogTitle className="text-base font-semibold text-[#222222]">
                    Cấp quyền truy cập trực tiếp (Direct Grant)
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-[#717171]">
                  Chủ sở hữu cấp quyền đọc/tải có thời hạn cho Người dùng hoặc Vai trò cụ thể
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleCreateDirectGrant} className="space-y-3.5 py-2 text-xs">
                <div className="space-y-1">
                  <label htmlFor="direct-doc" className="font-medium text-[#222222]">
                    Chọn tài liệu cấp quyền <span className="text-[#C13515]">*</span>
                  </label>
                  <select
                    id="direct-doc"
                    value={directDocId}
                    onChange={(e) => setDirectDocId(e.target.value)}
                    className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                  >
                    {documents.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.title} ({d.classificationCode})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-[#222222] block">Loại đối tượng được cấp:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setDirectPrincipalType('USER')}
                      className={`py-2 px-3 rounded-full border text-xs font-semibold cursor-pointer ${
                        directPrincipalType === 'USER'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white'
                          : 'border-[#dddddd] bg-white text-[#222222]'
                      }`}
                    >
                      Người dùng (USER)
                    </button>
                    <button
                      type="button"
                      onClick={() => setDirectPrincipalType('ROLE')}
                      className={`py-2 px-3 rounded-full border text-xs font-semibold cursor-pointer ${
                        directPrincipalType === 'ROLE'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white'
                          : 'border-[#dddddd] bg-white text-[#222222]'
                      }`}
                    >
                      Vai trò (ROLE)
                    </button>
                  </div>
                </div>

                {directPrincipalType === 'USER' ? (
                  <div className="space-y-1">
                    <label htmlFor="direct-user" className="font-medium text-[#222222]">
                      Chọn người dùng <span className="text-[#C13515]">*</span>
                    </label>
                    <select
                      id="direct-user"
                      value={directUserId}
                      onChange={(e) => setDirectUserId(e.target.value)}
                      className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                    >
                      {usersLookup.map((u) => (
                        <option key={u.id} value={u.id}>
                          {u.fullName} ({u.username}) · {u.departmentName} · Cấp mật Rank{' '}
                          {u.clearanceRank}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <label htmlFor="direct-role" className="font-medium text-[#222222]">
                      Chọn vai trò <span className="text-[#C13515]">*</span>
                    </label>
                    <select
                      id="direct-role"
                      value={directRoleId}
                      onChange={(e) => setDirectRoleId(e.target.value)}
                      className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                    >
                      {rolesLookup.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.name} ({r.code})
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                {/* BELL-LAPADULA CLEARANCE CHECK WARNING */}
                {isClearanceWarning && (
                  <div className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/5 p-3 text-[11px] text-[#C13515] space-y-1">
                    <div className="flex items-center gap-1.5 font-bold">
                      <AlertTriangle className="h-4 w-4" />
                      <span>Cảnh báo Clearance (D-BR04):</span>
                    </div>
                    <div>
                      Người dùng {selectedDirectUser?.fullName} có bậc Clearance Rank{' '}
                      {selectedDirectUser?.clearanceRank}, thấp hơn mức mật của tài liệu (Rank{' '}
                      {selectedDirectDoc?.classificationRank}). Hệ thống ABAC sẽ từ chối cấp quyền
                      hoặc người dùng không thể giải mã tài liệu!
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <span className="font-medium text-[#222222] block">Quyền hạn cấp:</span>
                  <div className="flex gap-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={directPermissions.includes('VIEW')}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setDirectPermissions((prev) => Array.from(new Set([...prev, 'VIEW'])));
                          } else {
                            setDirectPermissions((prev) => prev.filter((p) => p !== 'VIEW'));
                          }
                        }}
                        className="rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
                      />
                      <span>Chỉ xem trực tuyến (VIEW)</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={directPermissions.includes('DOWNLOAD')}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setDirectPermissions((prev) =>
                              Array.from(new Set([...prev, 'DOWNLOAD'])),
                            );
                          } else {
                            setDirectPermissions((prev) => prev.filter((p) => p !== 'DOWNLOAD'));
                          }
                        }}
                        className="rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
                      />
                      <span>Tải về có Watermark (DOWNLOAD)</span>
                    </label>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label htmlFor="valid-from" className="font-medium text-[#222222]">
                      Thời điểm bắt đầu:
                    </label>
                    <Input
                      id="valid-from"
                      type="datetime-local"
                      value={directValidFrom}
                      onChange={(e) => setDirectValidFrom(e.target.value)}
                      className="h-8 text-xs rounded-full bg-white border-[#dddddd]"
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="valid-until" className="font-medium text-[#222222]">
                      Thời điểm kết thúc:
                    </label>
                    <Input
                      id="valid-until"
                      type="datetime-local"
                      value={directValidUntil}
                      onChange={(e) => setDirectValidUntil(e.target.value)}
                      className="h-8 text-xs rounded-full bg-white border-[#dddddd]"
                    />
                  </div>
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setDirectGrantOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="primary"
                    size="sm"
                    text={isSubmittingDirectGrant ? 'Đang cấp...' : 'Xác nhận cấp quyền'}
                    disabled={isSubmittingDirectGrant}
                    isLoading={isSubmittingDirectGrant}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* RECLASSIFY DOCUMENT MODAL */}
          <Dialog open={reclassifyOpen} onOpenChange={setReclassifyOpen}>
            <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-[#FF385C]" />
                  <DialogTitle className="text-base font-semibold text-[#222222]">
                    Điều chỉnh phân loại mật (Reclassify)
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-[#717171]">
                  Lịch sử phân loại SCD Type 2 sẽ được ghi nhận phục vụ kiểm toán
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleConfirmReclassify} className="space-y-3.5 py-2 text-xs">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
                  <div>
                    Tài liệu: <strong>{docForReclassify?.title}</strong>
                  </div>
                  <div>
                    Mức mật hiện tại:{' '}
                    <ClassificationBadge
                      level={docForReclassify?.classificationCode ?? 'CONFIDENTIAL'}
                      size="sm"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="reclass-level" className="font-medium text-[#222222]">
                    Mức độ mật mới <span className="text-[#C13515]">*</span>
                  </label>
                  <select
                    id="reclass-level"
                    value={reclassLevelId}
                    onChange={(e) => setReclassLevelId(Number(e.target.value))}
                    className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                  >
                    {classificationLevels.map((lvl) => (
                      <option key={lvl.id} value={lvl.id}>
                        {lvl.name} ({lvl.code}) · Rank {lvl.rank}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label htmlFor="reclass-cat" className="font-medium text-[#222222]">
                    Danh mục nghiệp vụ <span className="text-[#C13515]">*</span>
                  </label>
                  <select
                    id="reclass-cat"
                    value={reclassCategoryId}
                    onChange={(e) => setReclassCategoryId(Number(e.target.value))}
                    className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                  >
                    {businessCategories.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.code})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label htmlFor="reclass-reason" className="font-medium text-[#222222]">
                    Lý do điều chỉnh (Kiểm toán bắt buộc) <span className="text-[#C13515]">*</span>
                  </label>
                  <Textarea
                    id="reclass-reason"
                    required
                    rows={3}
                    value={reclassReason}
                    onChange={(e) => setReclassReason(e.target.value)}
                    placeholder="Ví dụ: Hạ cấp độ mật sau khi báo cáo được công bố chính thức..."
                    className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
                  />
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setReclassifyOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="primary"
                    size="sm"
                    text="Lưu thay đổi"
                    disabled={isReclassifying}
                    isLoading={isReclassifying}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* NEW VERSION UPLOAD MODAL */}
          <Dialog open={newVersionOpen} onOpenChange={setNewVersionOpen}>
            <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <div className="flex items-center gap-2">
                  <Layers className="h-5 w-5 text-[#008489]" />
                  <DialogTitle className="text-base font-semibold text-[#222222]">
                    Cập nhật phiên bản tài liệu mới
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-[#717171]">
                  Tải lên tệp mới để tăng số phiên bản cho tài liệu &quot;{docForNewVersion?.title}
                  &quot;
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleConfirmNewVersion} className="space-y-3.5 py-2 text-xs">
                <div className="space-y-1">
                  <label htmlFor="new-version-file" className="font-medium text-[#222222]">
                    Chọn tệp phiên bản mới <span className="text-[#C13515]">*</span>
                  </label>
                  <input
                    id="new-version-file"
                    type="file"
                    required
                    accept=".pdf,.docx,.xlsx,.pptx"
                    onChange={(e) => setNewVersionFile(e.target.files?.[0] || null)}
                    className="w-full text-xs text-[#717171] file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-[#f7f7f7] file:text-xs file:font-medium file:text-[#222222] hover:file:bg-[#ebebeb] cursor-pointer"
                  />
                </div>

                <div className="space-y-1">
                  <label htmlFor="new-version-note" className="font-medium text-[#222222]">
                    Ghi chú thay đổi (Change Note)
                  </label>
                  <Input
                    id="new-version-note"
                    value={newVersionNote}
                    onChange={(e) => setNewVersionNote(e.target.value)}
                    placeholder="Ví dụ: Bổ sung phụ lục giải trình tài chính..."
                    className="h-8 text-xs rounded-full bg-white border-[#dddddd]"
                  />
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setNewVersionOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="primary"
                    size="sm"
                    text="Tải lên phiên bản"
                    disabled={isUploadingVersion || !newVersionFile}
                    isLoading={isUploadingVersion}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* ARCHIVE DOCUMENT MODAL */}
          <Dialog open={archiveOpen} onOpenChange={setArchiveOpen}>
            <DialogContent className="max-w-md border border-[#C13515]/20 bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <div className="flex items-center gap-2 text-[#C13515]">
                  <Archive className="h-5 w-5" />
                  <DialogTitle className="text-base font-semibold text-[#C13515]">
                    Lưu trữ tài liệu (Archive)
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-[#717171]">
                  Tài liệu sẽ bị đóng băng (ARCHIVED). Toàn bộ giấy phép truy cập sẽ bị tạm ngưng và
                  các phiên đọc hiện hành sẽ bị ngắt lập tức.
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleConfirmArchive} className="space-y-3.5 py-2 text-xs">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
                  <div>
                    Tài liệu: <strong>{docForArchive?.title}</strong>
                  </div>
                  <div>Mã số: {docForArchive?.documentCode}</div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="archive-reason" className="font-medium text-[#222222]">
                    Lý do lưu trữ
                  </label>
                  <Textarea
                    id="archive-reason"
                    rows={3}
                    value={archiveReason}
                    onChange={(e) => setArchiveReason(e.target.value)}
                    placeholder="Ví dụ: Tài liệu đã hoàn thành chu kỳ sử dụng và lưu kho an toàn..."
                    className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222]"
                  />
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setArchiveOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="danger"
                    size="sm"
                    text="Xác nhận lưu trữ"
                    disabled={isArchiving}
                    isLoading={isArchiving}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* VERSION HISTORY MODAL */}
          <Dialog open={versionHistoryOpen} onOpenChange={setVersionHistoryOpen}>
            <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader className="flex flex-row items-center justify-between">
                <div>
                  <DialogTitle className="text-base font-semibold text-[#222222]">
                    Lịch sử các phiên bản: {docForVersions?.title}
                  </DialogTitle>
                  <DialogDescription className="text-xs text-[#717171]">
                    Danh sách các tệp nguồn, băm SHA-256 và trạng thái quét virus từng phiên bản
                  </DialogDescription>
                </div>
                <InteractiveHoverButton
                  variant="ghost"
                  size="sm"
                  text="Xem lịch sử phân loại"
                  onClick={() => {
                    setVersionHistoryOpen(false);
                    if (docForVersions) {
                      void handleOpenClassHistory(docForVersions);
                    }
                  }}
                />
              </DialogHeader>

              <div className="py-2 text-xs">
                {isLoadingVersions ? (
                  <div className="text-center py-6 text-[#717171]">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-[#FF385C]" />
                    Đang tải lịch sử phiên bản...
                  </div>
                ) : docVersions.length === 0 ? (
                  <div className="text-center py-6 text-[#717171]">Không có dữ liệu phiên bản</div>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {docVersions.map((v) => (
                      <div
                        key={v.id}
                        className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[#222222]">
                            Phiên bản v{v.versionNo}.0
                          </span>
                          <Badge
                            variant={v.scanStatus === 'CLEAN' ? 'success' : 'destructive'}
                            className="text-[10px]"
                          >
                            {v.scanStatus}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-1 text-[11px] text-[#717171]">
                          <div>
                            Tệp: <strong className="text-[#222222]">{v.originalFilename}</strong>
                          </div>
                          <div>Kích thước: {(Number(v.fileSizeBytes) / 1024).toFixed(1)} KB</div>
                          <div>Thời điểm: {new Date(v.createdAt).toLocaleString('vi-VN')}</div>
                          <div>Ghi chú: {v.changeNote || '—'}</div>
                        </div>
                        <div className="text-[10px] text-[#717171] font-mono truncate">
                          SHA-256: {v.sha256Hash}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <DialogFooter>
                <InteractiveHoverButton
                  variant="secondary"
                  size="sm"
                  text="Đóng"
                  onClick={() => setVersionHistoryOpen(false)}
                />
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* CLASSIFICATION HISTORY MODAL */}
          <Dialog open={classHistoryOpen} onOpenChange={setClassHistoryOpen}>
            <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Lịch sử phân loại SCD Type 2: {docForClassHistory?.title}
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Truy vết thay đổi mức độ mật và danh mục nghiệp vụ qua các thời kỳ
                </DialogDescription>
              </DialogHeader>

              <div className="py-2 text-xs">
                {isLoadingClassHistory ? (
                  <div className="text-center py-6 text-[#717171]">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-[#FF385C]" />
                    Đang tải lịch sử phân loại...
                  </div>
                ) : docClassHistory.length === 0 ? (
                  <div className="text-center py-6 text-[#717171]">
                    Không có dữ liệu lịch sử phân loại
                  </div>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {docClassHistory.map((ch) => (
                      <div
                        key={ch.id}
                        className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <ClassificationBadge level={ch.classificationLevelCode} size="sm" />
                            <span className="font-semibold text-[#222222]">
                              {ch.businessCategoryName}
                            </span>
                          </div>
                          <span className="text-[10px] text-[#717171]">
                            {ch.effectiveTo ? (
                              `Hiệu lực đến: ${new Date(ch.effectiveTo).toLocaleDateString('vi-VN')}`
                            ) : (
                              <Badge variant="success" className="text-[10px]">
                                Đang hiệu lực
                              </Badge>
                            )}
                          </span>
                        </div>
                        <div className="text-[11px] text-[#717171]">
                          <div>
                            Hiệu lực từ: {new Date(ch.effectiveFrom).toLocaleString('vi-VN')}
                          </div>
                          <div>
                            Lý do: <span className="text-[#222222]">{ch.reason || '—'}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <DialogFooter>
                <InteractiveHoverButton
                  variant="secondary"
                  size="sm"
                  text="Đóng"
                  onClick={() => setClassHistoryOpen(false)}
                />
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* AUDIT LOG DETAIL MODAL */}
          <Dialog open={auditDetailOpen} onOpenChange={setAuditDetailOpen}>
            <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Chi tiết bản ghi kiểm toán #{selectedAuditLog?.id}
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Chữ ký chuỗi Merkle/Hash chain đảm bảo tính toàn vẹn không thể làm giả
                </DialogDescription>
              </DialogHeader>

              {selectedAuditLog && (
                <div className="py-2 text-xs space-y-2">
                  <div className="grid grid-cols-2 gap-2 bg-[#f7f7f7] p-3 rounded-[20px] border border-[#ebebeb]">
                    <div>
                      Thời điểm:{' '}
                      <strong>
                        {new Date(selectedAuditLog.occurredAt).toLocaleString('vi-VN')}
                      </strong>
                    </div>
                    <div>
                      Hành động: <strong>{selectedAuditLog.action}</strong>
                    </div>
                    <div>
                      Người dùng: <strong>{selectedAuditLog.actorUsername || 'system'}</strong>
                    </div>
                    <div>
                      Kết quả:{' '}
                      <Badge
                        variant={selectedAuditLog.outcome === 'SUCCESS' ? 'success' : 'destructive'}
                        className="text-[10px]"
                      >
                        {selectedAuditLog.outcome}
                      </Badge>
                    </div>
                    <div>
                      IP: <span className="font-mono">{selectedAuditLog.ipAddress || '—'}</span>
                    </div>
                    <div>
                      Phiên:{' '}
                      <span className="font-mono">{selectedAuditLog.accessSessionId || '—'}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="font-medium text-[#222222]">
                      Hash chuỗi kiểm toán (Entry Hash):
                    </span>
                    <div className="p-2 rounded bg-[#f7f7f7] border font-mono text-[10px] break-all text-[#717171]">
                      {selectedAuditLog.entryHash}
                    </div>
                  </div>

                  {selectedAuditLog.details && Object.keys(selectedAuditLog.details).length > 0 && (
                    <div className="space-y-1">
                      <span className="font-medium text-[#222222]">
                        Thuộc tính chi tiết (Details):
                      </span>
                      <pre className="p-2 rounded bg-[#f7f7f7] border font-mono text-[10px] text-[#222222] overflow-x-auto max-h-36">
                        {JSON.stringify(selectedAuditLog.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              <DialogFooter>
                <InteractiveHoverButton
                  variant="secondary"
                  size="sm"
                  text="Đóng"
                  onClick={() => setAuditDetailOpen(false)}
                />
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* REVOKE GRANT MODAL */}
          <Dialog open={revokeOpen} onOpenChange={setRevokeOpen}>
            <DialogContent className="max-w-md border border-[#C13515]/20 bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <div className="flex items-center gap-2 text-[#C13515]">
                  <AlertOctagon className="h-5 w-5" />
                  <DialogTitle className="text-base font-semibold text-[#C13515]">
                    Thu hồi giấy phép truy cập khẩn cấp
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-[#717171]">
                  D-BR15: Bắt buộc nêu rõ lý do thu hồi (ít nhất 10 ký tự). Mọi phiên làm việc đang
                  chạy sẽ bị ngắt lập tức.
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleConfirmRevoke} className="space-y-3.5 py-2">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 text-xs space-y-1">
                  <div>
                    Đối tượng:{' '}
                    <strong className="text-[#222222]">{selectedGrant?.principalName}</strong>
                  </div>
                  <div>
                    Tài liệu: <span className="text-[#222222]">{selectedGrant?.documentTitle}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="revoke-reason" className="text-xs font-medium text-[#222222]">
                    Lý do thu hồi (Ghi vào Audit Trail) <span className="text-[#C13515]">*</span>
                  </label>
                  <Textarea
                    id="revoke-reason"
                    required
                    rows={3}
                    value={revokeReason}
                    onChange={(e) => setRevokeReason(e.target.value)}
                    placeholder="Ví dụ: Dự án đã hoàn thành trước hạn; hoặc có dấu hiệu rò rỉ thông tin..."
                    className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                  />
                  <p className="text-[10px] text-[#717171]">
                    Tối thiểu 10 ký tự ({revokeReason.trim().length}/10)
                  </p>
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setRevokeOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="danger"
                    size="sm"
                    text="Xác nhận thu hồi ngay"
                    disabled={isRevoking || revokeReason.trim().length < 10}
                    isLoading={isRevoking}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* APPROVE REQUEST MODAL */}
          <Dialog open={approveOpen} onOpenChange={setApproveOpen}>
            <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Cấp giấy phép truy cập có thời hạn
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Xác định quyền (VIEW hoặc DOWNLOAD) và giới hạn thời gian hiệu lực
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3.5 py-2 text-xs">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
                  <div>
                    Người nhận quyền:{' '}
                    <strong className="text-[#222222]">{selectedRequest?.requestorName}</strong>
                  </div>
                  <div>
                    Tài liệu:{' '}
                    <span className="text-[#222222]">{selectedRequest?.documentTitle}</span>
                  </div>
                  {selectedRequest?.requestedFrom && selectedRequest?.requestedUntil && (
                    <div className="text-[#008489] font-medium pt-1 border-t border-[#ebebeb]">
                      Thời gian yêu cầu:{' '}
                      {new Date(selectedRequest.requestedFrom).toLocaleDateString('vi-VN')} đến{' '}
                      {new Date(selectedRequest.requestedUntil).toLocaleDateString('vi-VN')}
                    </div>
                  )}
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-[#222222] block">Phạm vi quyền cấp:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setGrantAction('VIEW')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold cursor-pointer ${
                        grantAction === 'VIEW'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd]'
                      }`}
                    >
                      <Eye className="h-4 w-4" />
                      <span>Chỉ xem (VIEW)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setGrantAction('DOWNLOAD')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold cursor-pointer ${
                        grantAction === 'DOWNLOAD'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd]'
                      }`}
                    >
                      <Download className="h-4 w-4" />
                      <span>Xem & Tải (DOWNLOAD)</span>
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="grant-duration" className="font-medium text-[#222222]">
                    Thời hạn hiệu lực (Ngày):
                  </label>
                  <select
                    id="grant-duration"
                    value={grantValidDays}
                    onChange={(e) => setGrantValidDays(Number(e.target.value))}
                    className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                  >
                    <option value={1}>1 ngày (24 giờ khẩn cấp)</option>
                    <option value={3}>3 ngày</option>
                    <option value={7}>7 ngày (1 tuần làm việc)</option>
                    <option value={14}>14 ngày</option>
                    <option value={30}>30 ngày</option>
                  </select>
                </div>
              </div>

              <DialogFooter className="pt-2">
                <InteractiveHoverButton
                  type="button"
                  variant="ghost"
                  size="sm"
                  text="Hủy"
                  onClick={() => setApproveOpen(false)}
                />
                <InteractiveHoverButton
                  type="button"
                  variant="primary"
                  size="sm"
                  text="Xác nhận cấp quyền"
                  disabled={isApproving}
                  isLoading={isApproving}
                  onClick={() => void handleConfirmApprove()}
                />
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* SECURE SANDBOX PREVIEW MODAL */}
          <Dialog open={previewOpen} onOpenChange={handleClosePreview}>
            <DialogContent className="max-w-4xl max-h-[92vh] flex flex-col border-[#ebebeb] bg-[#f7f7f7] text-[#222222] p-0 overflow-hidden">
              <DialogHeader className="p-4 border-b border-[#ebebeb] bg-[#ffffff] flex flex-row items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-[#008A05]" />
                    <DialogTitle className="text-sm font-semibold text-[#222222]">
                      Sandbox Xem Trước An Toàn: {previewDoc?.title}
                    </DialogTitle>
                  </div>
                  <DialogDescription className="text-[11px] text-[#717171] mt-0.5 flex flex-wrap items-center gap-2">
                    <span>Phiên: {previewSessionId || 'sess-active'}</span>
                    <span className="text-[#ebebeb]">|</span>
                    <span className="inline-flex items-center gap-1 text-[#008489] font-medium">
                      <FileType size={13} /> Pipeline Gotenberg: Office &rarr; Watermarked PDF
                    </span>
                  </DialogDescription>
                </div>

                {previewDoc && (
                  <ClassificationBadge level={previewDoc.classificationCode} size="sm" />
                )}
              </DialogHeader>

              {/* Sandbox Viewer Area */}
              <div className="relative flex-1 bg-[#f7f7f7] flex flex-col items-center justify-center p-4 overflow-hidden min-h-[480px]">
                {isLoadingPreview ? (
                  <div className="flex flex-col items-center gap-3">
                    <RefreshCw className="h-8 w-8 animate-spin text-[#FF385C]" />
                    <p className="text-xs text-[#717171]">
                      Đang xử lý trang tài liệu và nhúng dấu Watermark động…
                    </p>
                  </div>
                ) : previewPdfUrl ? (
                  <div className="w-full flex-1 flex flex-col items-center justify-center min-h-[500px]">
                    <iframe
                      src={`${previewPdfUrl}#toolbar=0&navpanes=0`}
                      className="w-full h-[520px] rounded border border-[#dddddd] bg-white shadow-sm"
                      title={previewDoc?.title || 'Preview tài liệu'}
                    />
                  </div>
                ) : (
                  <div className="relative w-full max-w-2xl aspect-[3/4] bg-white rounded shadow-2xl p-8 flex flex-col justify-between overflow-hidden select-none border border-[#dddddd]">
                    {/* Simulated document contents */}
                    <div className="space-y-4 text-[#222222]">
                      <div className="border-b border-[#ebebeb] pb-3">
                        <div className="text-[11px] font-bold uppercase tracking-wider text-[#717171]">
                          CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM
                        </div>
                        <div className="text-xs font-semibold text-[#222222] mt-1">
                          {previewDoc?.title}
                        </div>
                        <div className="text-[10px] text-[#717171] font-bold mt-0.5">
                          Số: {previewDoc?.documentCode || 'DOC-CONFIDENTIAL-2026'}
                        </div>
                      </div>

                      <div className="space-y-2 text-xs leading-relaxed text-[#717171]">
                        <p>
                          Căn cứ quy chế an toàn thông tin và bảo vệ tài liệu mật số 14/QC-BCĐ, nội
                          dung này chỉ được phép tiếp cận bởi nhân sự được ủy quyền thông qua phiên
                          làm việc đã xác thực.
                        </p>
                        <p>
                          Nghiêm cấm sao chép, chụp ảnh màn hình hoặc phát tán ra ngoài phạm vi quy
                          định. Mọi vi phạm sẽ được xử lý theo quy định của pháp luật và truy vết
                          qua mã watermark định danh phiên.
                        </p>
                      </div>
                    </div>

                    {/* DYNAMIC WATERMARK OVERLAY */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] opacity-25">
                      <div className="font-bold text-center text-[#C13515] text-sm leading-tight space-y-1">
                        <div>
                          {user?.fullName || 'CHỦ SỞ HỮU'} · {user?.username}
                        </div>
                        <div>{new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC</div>
                        <div className="text-xs text-[#222222]">{previewDoc?.documentCode}</div>
                        <div className="text-[11px] text-[#008A05]">
                          WM-{previewSessionId?.slice(0, 16)}
                        </div>
                      </div>
                      <div className="mt-2 p-1 border border-[#C13515] rounded bg-white/80">
                        <QrCode className="h-9 w-9 text-[#C13515]" />
                      </div>
                    </div>

                    <div className="text-[10px] font-bold text-[#717171] flex justify-between border-t border-[#ebebeb] pt-2">
                      <span>Phân hệ Owner · Controlled Delivery</span>
                      <span>
                        Trang {previewPage} / {previewTotalPages}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer with page controls */}
              <div className="p-3 border-t border-[#ebebeb] bg-[#ffffff] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <InteractiveHoverButton
                    size="sm"
                    variant="secondary"
                    text="Trang trước"
                    icon={<ChevronLeft size={16} />}
                    disabled={previewPage <= 1 || isLoadingPreview}
                    onClick={() => void handlePageChange(Math.max(1, previewPage - 1))}
                  />
                  <span className="text-xs font-bold text-[#717171]">
                    Trang {previewPage} / {previewTotalPages}
                  </span>
                  <InteractiveHoverButton
                    size="sm"
                    variant="secondary"
                    text="Trang sau"
                    icon={<ChevronRight size={16} />}
                    disabled={previewPage >= previewTotalPages || isLoadingPreview}
                    onClick={() =>
                      void handlePageChange(Math.min(previewTotalPages, previewPage + 1))
                    }
                  />
                </div>

                <InteractiveHoverButton
                  size="sm"
                  variant="secondary"
                  text="Đóng Sandbox"
                  onClick={() => handleClosePreview(false)}
                />
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
