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
} from 'lucide-react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
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

interface DocumentItem {
  id: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  classificationRank?: number | undefined;
  status: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
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
  classification?: { code?: ClassificationCode; rank?: number };
  status?: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  department?: { name?: string };
  allowDownload?: boolean;
  versions?: unknown[];
  createdAt?: string;
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

export function OwnerWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('documents');
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);

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
  const previewTotalPages = 3;
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);

  // 3-step Upload Wizard State
  const [uploadWizardOpen, setUploadWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState<1 | 2 | 3>(1);
  const [docFile, setDocFile] = useState<File | null>(null);
  const [docTitle, setDocTitle] = useState('');
  const [docCode, setDocCode] = useState('');
  const [docDescription, setDocDescription] = useState('');
  const [docClassification, setDocClassification] = useState<ClassificationCode>('CONFIDENTIAL');
  const [docAllowDownload, setDocAllowDownload] = useState(true);
  const [docRetentionDate, setDocRetentionDate] = useState('');
  const [isSubmittingDoc, setIsSubmittingDoc] = useState(false);

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

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [docsRes, grantsRes, requestsRes] = await Promise.all([
        apiClient<{ data: DocumentApiDto[] }>('/documents?pageSize=50').catch(() => ({ data: [] })),
        apiClient<{ data: AccessGrantApiDto[] }>('/access-grants?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: AccessRequestItem[] }>(
          '/access-requests?scope=incoming&status=PENDING',
        ).catch(() => ({ data: [] })),
      ]);

      const mappedDocs: DocumentItem[] = (docsRes.data || []).map((d) => ({
        id: d.id,
        title: d.title || 'Tài liệu không tên',
        documentCode: d.documentCode || d.document_code,
        classificationCode: (d.classification?.code ||
          d.classificationCode ||
          'CONFIDENTIAL') as ClassificationCode,
        classificationRank: d.classification?.rank ?? 3,
        status: d.status || 'ACTIVE',
        departmentName: d.department?.name || 'Phòng Kỹ thuật & Nghiệp vụ',
        allowDownload: d.allowDownload ?? true,
        versionCount: d.versions?.length ?? 1,
        createdAt: d.createdAt || new Date().toISOString(),
      }));
      setDocuments(mappedDocs);

      const mappedGrants: AccessGrantItem[] = (grantsRes.data || []).map((g) => ({
        id: g.id,
        documentId: g.documentId,
        documentTitle: g.document?.title || 'Tài liệu số ' + g.documentId.slice(0, 8),
        principalType: g.principalType || 'USER',
        principalName:
          g.principalUser?.fullName || g.principalRole?.name || 'Nhân sự được ủy quyền',
        permissions: g.permissions || ['VIEW'],
        validFrom: g.validFrom || new Date().toISOString(),
        validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
        status: g.status || 'ACTIVE',
        version: g.version || 0,
      }));
      setGrants(mappedGrants);

      const mappedRequests: AccessRequestItem[] = (requestsRes.data || []).map((r) => ({
        id: r.id,
        documentId: r.documentId,
        documentTitle: r.documentTitle || 'Tài liệu mật',
        requestorName: r.requestorName || 'Nhân viên yêu cầu',
        requestorDepartment: r.requestorDepartment || 'Chung',
        requestedAction: r.requestedAction || 'VIEW',
        justification: r.justification || '',
        status: r.status || 'PENDING',
        createdAt: r.createdAt || new Date().toISOString(),
      }));
      setRequests(mappedRequests);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể tải danh sách tài liệu và quyền truy cập.');
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshData();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refreshData]);

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
        const objectUrl = URL.createObjectURL(pdfBlob);
        setPreviewPdfUrl(objectUrl);
      } catch (streamErr) {
        console.warn(
          'Could not load binary PDF preview stream, using sandbox canvas fallback:',
          streamErr,
        );
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

  // Handle Create Document Draft (3-step wizard submit)
  async function handleFinishUpload() {
    setIsSubmittingDoc(true);
    setErrorMessage(null);
    try {
      await apiClient('/documents', {
        method: 'POST',
        body: JSON.stringify({
          title: docTitle.trim(),
          documentCode: docCode.trim() || undefined,
          departmentId: 1, // Current user department
          description: docDescription.trim() || undefined,
          classificationLevelId:
            docClassification === 'UNCLASSIFIED'
              ? 1
              : docClassification === 'RESTRICTED'
                ? 2
                : docClassification === 'CONFIDENTIAL'
                  ? 3
                  : docClassification === 'SECRET'
                    ? 4
                    : 5,
          retentionUntil: docRetentionDate || undefined,
        }),
      });

      setMessage(`Tài liệu "${docTitle}" đã được tạo thành công với mức mật ${docClassification}.`);
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
        setErrorMessage(err.message || 'Không thể tạo tài liệu mới.');
      } else {
        setErrorMessage('Đã xảy ra lỗi trong quá trình tải lên tài liệu.');
      }
    } finally {
      setIsSubmittingDoc(false);
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

  const filteredDocs = documents.filter((d) => {
    const q = searchQuery.toLowerCase();
    return (
      d.title.toLowerCase().includes(q) ||
      (d.documentCode && d.documentCode.toLowerCase().includes(q))
    );
  });

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
                Tải lên với phân loại mật bắt buộc, xét duyệt yêu cầu đọc/tải và thu hồi quyền có
                thời hạn
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
                      Mỗi tài liệu bắt buộc gắn nhãn mức mật rõ ràng và chính sách kiểm soát tải về
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
                            Mức độ mật (Multi-modal)
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                          <TableHead className="text-xs text-[#717171]">Phiên bản</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Thao tác
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDocs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={6}
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
                                <Badge variant="success">{doc.status}</Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex items-center justify-end gap-1.5">
                                  <InteractiveHoverButton
                                    variant="secondary"
                                    size="sm"
                                    text="Xem"
                                    icon={<Eye size={14} />}
                                    onClick={() => void handleOpenPreview(doc)}
                                    disabled={isLoadingPreview || doc.status !== 'ACTIVE'}
                                  />
                                  <InteractiveHoverButton
                                    variant={doc.allowDownload ? 'secondary' : 'ghost'}
                                    size="sm"
                                    text="Tải"
                                    icon={<Download size={14} />}
                                    onClick={() => void handleDownloadWithTicket(doc)}
                                    disabled={
                                      !doc.allowDownload ||
                                      downloadingDocId === doc.id ||
                                      doc.status !== 'ACTIVE'
                                    }
                                    isLoading={downloadingDocId === doc.id}
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
                    Xét duyệt yêu cầu đọc hoặc tải tài liệu mật từ các phòng ban nghiệp vụ
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
                              colSpan={5}
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
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Giấy phép truy cập có thời hạn (Access Grants)
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Cấp cho User hoặc Role; quyền hết hạn hoặc bị thu hồi sẽ chấm dứt mọi phiên đọc
                    lập tức
                  </CardDescription>
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

            {/* TAB 4: ACCESS HISTORY */}
            <TabsContent value="history" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Dấu vết truy cập tài liệu mật (Audit Log)
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Theo dõi đầy đủ sự kiện VIEW / DOWNLOAD gắn với mã định danh phiên và dấu bản
                    quyền
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-3 text-xs">
                    <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-[#008A05]" />
                        <span className="font-semibold text-[#222222]">
                          Truy cập hợp lệ gần nhất
                        </span>
                      </div>
                      <span className="font-bold text-[11px] text-[#717171]">
                        2026-09-23 12:45 UTC
                      </span>
                    </div>
                    <div className="grid gap-2 sm:grid-cols-2 text-[#222222]">
                      <div>
                        Người thực hiện:{' '}
                        <span className="text-[#222222] font-medium">Nguyen Van A</span>
                      </div>
                      <div>
                        Hành động:{' '}
                        <span className="font-bold text-[#008A05]">DOCUMENT:VIEW (Trang 1-5)</span>
                      </div>
                      <div>
                        Mã phiên (Session ID):{' '}
                        <span className="font-bold text-[11px] text-[#717171]">sess-99b8-1a2f</span>
                      </div>
                      <div>
                        Watermark Token:{' '}
                        <span className="font-bold text-[11px] text-[#E07912]">
                          WM-8f3a9b2c1e7d4410
                        </span>
                      </div>
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
                  {wizardStep === 1 && 'Bước 1: Chọn tập tin và gán mức độ mật bắt buộc'}
                  {wizardStep === 2 && 'Bước 2: Thiết lập chính sách tải về và thời hạn bảo quản'}
                  {wizardStep === 3 && 'Bước 3: Xác minh băm SHA-256 và xác nhận lưu trữ mã hóa'}
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
                        Chọn tệp tài liệu (PDF, DOCX, XLSX){' '}
                        <span className="text-[#C13515]">*</span>
                      </label>
                      <input
                        id="doc-file-upload"
                        type="file"
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
                        placeholder="Ví dụ: Báo cáo phương án tài chính nội bộ 2026"
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="doc-code" className="text-xs font-medium text-[#222222]">
                        Mã số tài liệu
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
                        {(
                          [
                            'UNCLASSIFIED',
                            'RESTRICTED',
                            'CONFIDENTIAL',
                            'SECRET',
                            'TOP_SECRET',
                          ] as ClassificationCode[]
                        ).map((level) => (
                          <button
                            key={level}
                            type="button"
                            onClick={() => setDocClassification(level)}
                            className={`flex flex-col items-center justify-center py-2 px-3 rounded-[40px] border text-center transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                              docClassification === level
                                ? 'border-[#FF385C] bg-[#FF385C]/10 ring-1 ring-[#FF385C]'
                                : 'border-[#ebebeb] bg-[#ffffff] hover:bg-[#f7f7f7] hover:border-[#dddddd]'
                            }`}
                          >
                            <ClassificationBadge level={level} size="sm" />
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

                    <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-xs font-medium text-[#222222]">
                            Chính sách cho phép tải về
                          </div>
                          <div className="text-[11px] text-[#717171]">
                            Nếu tắt, người đọc chỉ được xem trực tuyến qua sandbox bảo mật
                          </div>
                        </div>
                        <input
                          type="checkbox"
                          checked={docAllowDownload}
                          onChange={(e) => setDocAllowDownload(e.target.checked)}
                          className="h-4 w-4 rounded border-[#dddddd] bg-[#ffffff] accent-[#FF385C]"
                        />
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
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] text-[#222222]"
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
                        {docFile && (
                          <>
                            <span className="text-[#717171]">Tệp nguồn:</span>
                            <span className="font-bold text-[#222222]">{docFile.name}</span>
                          </>
                        )}
                        <span className="text-[#717171]">Mức độ mật:</span>
                        <ClassificationBadge level={docClassification} size="sm" />
                        <span className="text-[#717171]">Chính sách tải:</span>
                        <span>
                          {docAllowDownload ? 'Cho phép tải có watermark' : 'Chỉ xem trực tuyến'}
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
                    disabled={!docTitle.trim()}
                    onClick={() => setWizardStep((prev) => (prev + 1) as 2 | 3)}
                  />
                ) : (
                  <InteractiveHoverButton
                    type="button"
                    variant="primary"
                    size="sm"
                    text="Xác nhận tải lên"
                    disabled={isSubmittingDoc}
                    isLoading={isSubmittingDoc}
                    onClick={() => void handleFinishUpload()}
                  />
                )}
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
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-[#222222] block">Phạm vi quyền cấp:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setGrantAction('VIEW')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                        grantAction === 'VIEW'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                      }`}
                    >
                      <Eye className="h-4 w-4" />
                      <span>Chỉ xem (VIEW)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setGrantAction('DOWNLOAD')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                        grantAction === 'DOWNLOAD'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
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
                      <FileType size={13} /> Pipeline Gotenberg: Office (.docx/.xlsx/.pptx) &rarr;
                      Watermarked PDF
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
                      Đang chuyển đổi tệp Office sang PDF và đóng dấu Watermark…
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
                    disabled={previewPage <= 1}
                    onClick={() => setPreviewPage((p) => Math.max(1, p - 1))}
                  />
                  <span className="text-xs font-bold text-[#717171]">
                    Trang {previewPage} / {previewTotalPages}
                  </span>
                  <InteractiveHoverButton
                    size="sm"
                    variant="secondary"
                    text="Trang sau"
                    icon={<ChevronRight size={16} />}
                    disabled={previewPage >= previewTotalPages}
                    onClick={() => setPreviewPage((p) => Math.min(previewTotalPages, p + 1))}
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
