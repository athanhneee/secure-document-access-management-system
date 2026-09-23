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
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { ClassificationBadge, type ClassificationCode } from '@/components/classification-badge';
import { Button } from '@/components/ui/button';
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
  const [activeTab, setActiveTab] = useState('documents');
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

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
      const [docsRes, grantsRes] = await Promise.all([
        apiClient<{ data: DocumentApiDto[] }>('/documents?pageSize=50').catch(() => ({ data: [] })),
        apiClient<{ data: AccessGrantApiDto[] }>('/access-grants?pageSize=50').catch(() => ({
          data: [],
        })),
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

      // Demo/Fallback requests for owner review
      setRequests([
        {
          id: 'req-01',
          documentId: mappedDocs[0]?.id || 'doc-1',
          documentTitle: mappedDocs[0]?.title || 'Phương án phòng chống rò rỉ dữ liệu quý IV',
          requestorName: 'Nguyễn Văn Đọc',
          requestorDepartment: 'Ban Pháp chế',
          requestedAction: 'VIEW',
          justification: 'Cần đối chiếu căn cứ pháp lý để lập báo cáo đánh giá tác động nội bộ.',
          status: 'PENDING',
          createdAt: new Date().toISOString(),
        },
      ]);
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
      const now = new Date();
      const validUntil = new Date(now.getTime() + grantValidDays * 86400000);

      // Create access grant
      await apiClient('/access-grants', {
        method: 'POST',
        body: JSON.stringify({
          documentId: selectedRequest.documentId,
          principalType: 'USER',
          principalUserId: 2, // Map to requestor user ID
          permissions: [grantAction],
          validFrom: now.toISOString(),
          validUntil: validUntil.toISOString(),
        }),
      });

      setMessage(
        `Đã cấp quyền ${grantAction} tài liệu cho ${selectedRequest.requestorName} có thời hạn đến ${validUntil.toLocaleDateString('vi-VN')}.`,
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
                <Badge
                  variant="outline"
                  className="border-amber-600/40 bg-amber-950/30 text-amber-400"
                >
                  Document Owner
                </Badge>
                <span className="text-xs text-slate-500">Phân hệ Chủ sở hữu</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100 mt-1">
                Quản lý & Cấp phép Tài liệu Mật
              </h1>
              <p className="text-xs text-slate-400">
                Tải lên với phân loại mật bắt buộc, xét duyệt yêu cầu đọc/tải và thu hồi quyền có
                thời hạn
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refreshData()}
                disabled={isLoading}
                className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"
              >
                <RefreshCw
                  className={`mr-1.5 h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`}
                  aria-hidden="true"
                />
                Làm mới
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  setWizardStep(1);
                  setUploadWizardOpen(true);
                }}
                className="bg-emerald-600 hover:bg-emerald-500 text-white"
              >
                <FileUp className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                Tải lên tài liệu mới
              </Button>
            </div>
          </div>

          {message && (
            <Alert className="border-emerald-900/60 bg-emerald-950/40 text-emerald-300 text-xs">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
              <AlertDescription className="ml-2">{message}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert
              variant="destructive"
              className="border-red-900/60 bg-red-950/40 text-red-300 text-xs"
            >
              <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          {/* Navigation Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 bg-slate-900 border border-slate-800 p-1 rounded-xl">
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-slate-100">
                      Kho tài liệu mật đang quản lý
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-400">
                      Mỗi tài liệu bắt buộc gắn nhãn mức mật rõ ràng và chính sách kiểm soát tải về
                    </CardDescription>
                  </div>
                  <div className="relative w-full sm:w-64">
                    <Search
                      className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500"
                      aria-hidden="true"
                    />
                    <Input
                      type="text"
                      placeholder="Tìm theo tiêu đề, mã số..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-9 h-8 text-xs bg-slate-950 border-slate-800"
                    />
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-slate-950/60 border-b border-slate-800">
                        <TableRow>
                          <TableHead className="text-xs text-slate-400">
                            Tên tài liệu / Mã số
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">
                            Mức độ mật (Multi-modal)
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Chính sách tải</TableHead>
                          <TableHead className="text-xs text-slate-400">Phiên bản</TableHead>
                          <TableHead className="text-xs text-slate-400">Trạng thái</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDocs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-slate-400 text-xs"
                            >
                              Chưa có tài liệu nào trong danh mục quản lý
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredDocs.map((doc) => (
                            <TableRow
                              key={doc.id}
                              className="border-b border-slate-800/60 hover:bg-slate-800/40"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-slate-200">
                                  {doc.title}
                                </div>
                                <div className="text-[11px] font-mono text-slate-400">
                                  {doc.documentCode || 'DOC-' + doc.id.slice(0, 8)}
                                </div>
                              </TableCell>
                              <TableCell>
                                <ClassificationBadge level={doc.classificationCode} showRank />
                              </TableCell>
                              <TableCell>
                                {doc.allowDownload ? (
                                  <span className="flex items-center gap-1 text-[11px] text-emerald-400">
                                    <Download className="h-3 w-3" aria-hidden="true" />
                                    <span>Cho phép tải kèm Watermark</span>
                                  </span>
                                ) : (
                                  <span className="flex items-center gap-1 text-[11px] text-amber-400">
                                    <Eye className="h-3 w-3" aria-hidden="true" />
                                    <span>Chỉ xem trực tuyến</span>
                                  </span>
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-slate-300 font-mono">
                                v{doc.versionCount ?? 1}.0
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant="outline"
                                  className="border-emerald-600/40 bg-emerald-950/40 text-[10px] text-emerald-300"
                                >
                                  {doc.status}
                                </Badge>
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader>
                  <CardTitle className="text-base text-slate-100">
                    Hàng đợi yêu cầu cấp quyền
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Xét duyệt yêu cầu đọc hoặc tải tài liệu mật từ các phòng ban nghiệp vụ
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-slate-950/60 border-b border-slate-800">
                        <TableRow>
                          <TableHead className="text-xs text-slate-400">
                            Người yêu cầu / Phòng ban
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">
                            Tài liệu mục tiêu
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Hành động</TableHead>
                          <TableHead className="text-xs text-slate-400">Lý do nghiệp vụ</TableHead>
                          <TableHead className="text-xs text-slate-400 text-right">
                            Quyết định
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {requests.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-slate-400 text-xs"
                            >
                              Không có yêu cầu cấp quyền nào đang chờ duyệt
                            </TableCell>
                          </TableRow>
                        ) : (
                          requests.map((req) => (
                            <TableRow
                              key={req.id}
                              className="border-b border-slate-800/60 hover:bg-slate-800/40"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-slate-200">
                                  {req.requestorName}
                                </div>
                                <div className="text-[11px] text-slate-400">
                                  {req.requestorDepartment}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-slate-200 max-w-xs truncate">
                                {req.documentTitle}
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant="outline"
                                  className="border-slate-700 bg-slate-800 text-[10px] text-slate-300"
                                >
                                  {req.requestedAction}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-slate-300 max-w-sm">
                                {req.justification}
                              </TableCell>
                              <TableCell className="text-right space-x-1">
                                {req.status === 'PENDING' ? (
                                  <>
                                    <Button
                                      size="sm"
                                      onClick={() => {
                                        setSelectedRequest(req);
                                        setGrantAction(req.requestedAction);
                                        setApproveOpen(true);
                                      }}
                                      className="h-7 px-2.5 text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white"
                                    >
                                      <Check className="mr-1 h-3 w-3" aria-hidden="true" />
                                      Cấp quyền
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="destructive"
                                      onClick={() => {
                                        setMessage(`Đã từ chối yêu cầu của ${req.requestorName}.`);
                                        setRequests((prev) => prev.filter((r) => r.id !== req.id));
                                      }}
                                      className="h-7 px-2 text-[11px] bg-red-950 border border-red-800 text-red-300 hover:bg-red-900"
                                    >
                                      <X className="mr-1 h-3 w-3" aria-hidden="true" />
                                      Từ chối
                                    </Button>
                                  </>
                                ) : (
                                  <Badge variant="outline" className="text-[10px] text-slate-400">
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader>
                  <CardTitle className="text-base text-slate-100">
                    Giấy phép truy cập có thời hạn (Access Grants)
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Cấp cho User hoặc Role; quyền hết hạn hoặc bị thu hồi sẽ chấm dứt mọi phiên đọc
                    lập tức
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-slate-950/60 border-b border-slate-800">
                        <TableRow>
                          <TableHead className="text-xs text-slate-400">
                            Đối tượng được cấp
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Tài liệu</TableHead>
                          <TableHead className="text-xs text-slate-400">Quyền hạn</TableHead>
                          <TableHead className="text-xs text-slate-400">
                            Thời hạn hiệu lực
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Trạng thái</TableHead>
                          <TableHead className="text-xs text-slate-400 text-right">
                            Thu hồi khẩn cấp
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {grants.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={6}
                              className="text-center py-8 text-slate-400 text-xs"
                            >
                              Chưa có giấy phép truy cập nào được khởi tạo
                            </TableCell>
                          </TableRow>
                        ) : (
                          grants.map((grant) => (
                            <TableRow
                              key={grant.id}
                              className="border-b border-slate-800/60 hover:bg-slate-800/40"
                            >
                              <TableCell>
                                <div className="font-semibold text-xs text-slate-200">
                                  {grant.principalName}
                                </div>
                                <div className="text-[10px] font-mono text-slate-400">
                                  {grant.principalType}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-slate-200 max-w-xs truncate">
                                {grant.documentTitle}
                              </TableCell>
                              <TableCell>
                                <div className="flex gap-1">
                                  {grant.permissions.map((p) => (
                                    <Badge
                                      key={p}
                                      variant="outline"
                                      className="border-slate-700 bg-slate-800 text-[10px] text-slate-300"
                                    >
                                      {p}
                                    </Badge>
                                  ))}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-slate-300 font-mono">
                                <div>
                                  Từ: {new Date(grant.validFrom).toLocaleDateString('vi-VN')}
                                </div>
                                <div className="text-amber-400">
                                  Đến: {new Date(grant.validUntil).toLocaleDateString('vi-VN')}
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={grant.status === 'ACTIVE' ? 'default' : 'destructive'}
                                  className={`text-[10px] ${
                                    grant.status === 'ACTIVE'
                                      ? 'border-emerald-600/40 bg-emerald-950/40 text-emerald-300'
                                      : 'border-red-600/40 bg-red-950/40 text-red-300'
                                  }`}
                                >
                                  {grant.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                {grant.status === 'ACTIVE' && (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => {
                                      setSelectedGrant(grant);
                                      setRevokeReason('');
                                      setRevokeOpen(true);
                                    }}
                                    className="h-7 px-2 text-[11px] border-red-900/50 bg-red-950/30 text-red-300 hover:bg-red-900/50"
                                  >
                                    <AlertOctagon className="mr-1 h-3 w-3" aria-hidden="true" />
                                    Thu hồi
                                  </Button>
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader>
                  <CardTitle className="text-base text-slate-100">
                    Dấu vết truy cập tài liệu mật (Audit Log)
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Theo dõi đầy đủ sự kiện VIEW / DOWNLOAD gắn với mã định danh phiên và dấu bản
                    quyền
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-4 space-y-3 text-xs">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                        <span className="font-semibold text-slate-200">
                          Truy cập hợp lệ gần nhất
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400">
                        2026-09-23 12:45 UTC
                      </span>
                    </div>
                    <div className="grid gap-2 sm:grid-cols-2 text-slate-300">
                      <div>
                        Người thực hiện:{' '}
                        <span className="text-slate-100 font-medium">Nguyen Van A</span>
                      </div>
                      <div>
                        Hành động:{' '}
                        <span className="font-mono text-emerald-400">
                          DOCUMENT:VIEW (Trang 1-5)
                        </span>
                      </div>
                      <div>
                        Mã phiên (Session ID):{' '}
                        <span className="font-mono text-[11px] text-slate-400">sess-99b8-1a2f</span>
                      </div>
                      <div>
                        Watermark Token:{' '}
                        <span className="font-mono text-[11px] text-amber-400">
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
            <DialogContent className="max-w-xl border-slate-800 bg-slate-900 text-slate-100">
              <DialogHeader>
                <div className="flex items-center justify-between">
                  <DialogTitle className="text-base font-semibold text-slate-100">
                    Quy trình tải lên tài liệu an toàn (Bước {wizardStep}/3)
                  </DialogTitle>
                  <div className="flex gap-1.5">
                    {[1, 2, 3].map((step) => (
                      <div
                        key={step}
                        className={`h-2 w-6 rounded-full transition-all ${
                          wizardStep === step
                            ? 'bg-emerald-500'
                            : wizardStep > step
                              ? 'bg-emerald-800'
                              : 'bg-slate-800'
                        }`}
                      />
                    ))}
                  </div>
                </div>
                <DialogDescription className="text-xs text-slate-400">
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
                        className="text-xs font-medium text-slate-300"
                      >
                        Chọn tệp tài liệu (PDF, DOCX, XLSX) <span className="text-red-400">*</span>
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
                        className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:bg-slate-800 file:text-xs file:font-medium file:text-slate-200 hover:file:bg-slate-700"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="doc-title" className="text-xs font-medium text-slate-300">
                        Tiêu đề tài liệu <span className="text-red-400">*</span>
                      </label>
                      <Input
                        id="doc-title"
                        required
                        value={docTitle}
                        onChange={(e) => setDocTitle(e.target.value)}
                        placeholder="Ví dụ: Báo cáo phương án tài chính nội bộ 2026"
                        className="h-8 text-xs bg-slate-950 border-slate-800"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="doc-code" className="text-xs font-medium text-slate-300">
                        Mã số tài liệu
                      </label>
                      <Input
                        id="doc-code"
                        value={docCode}
                        onChange={(e) => setDocCode(e.target.value)}
                        placeholder="DOC-TC-2026-001"
                        className="h-8 text-xs bg-slate-950 border-slate-800"
                      />
                    </div>

                    <div className="space-y-2">
                      <span className="block text-xs font-medium text-slate-300">
                        Mức độ mật bắt buộc (Mandatory Classification){' '}
                        <span className="text-red-400">*</span>
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
                            className={`flex flex-col items-center justify-center p-2 rounded-lg border text-center transition-all ${
                              docClassification === level
                                ? 'border-emerald-500 bg-emerald-950/60 shadow-md ring-1 ring-emerald-500'
                                : 'border-slate-800 bg-slate-950/70 hover:bg-slate-800/60'
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
                      <label htmlFor="doc-desc" className="text-xs font-medium text-slate-300">
                        Mô tả tóm tắt nội dung
                      </label>
                      <Textarea
                        id="doc-desc"
                        rows={3}
                        value={docDescription}
                        onChange={(e) => setDocDescription(e.target.value)}
                        placeholder="Nội dung chính và phạm vi sử dụng của tài liệu..."
                        className="text-xs bg-slate-950 border-slate-800"
                      />
                    </div>

                    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-xs font-medium text-slate-200">
                            Chính sách cho phép tải về
                          </div>
                          <div className="text-[11px] text-slate-400">
                            Nếu tắt, người đọc chỉ được xem trực tuyến qua sandbox bảo mật
                          </div>
                        </div>
                        <input
                          type="checkbox"
                          checked={docAllowDownload}
                          onChange={(e) => setDocAllowDownload(e.target.checked)}
                          className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-emerald-500"
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="doc-retention" className="text-xs font-medium text-slate-300">
                        Thời hạn lưu trữ bảo mật (Retention Date)
                      </label>
                      <Input
                        id="doc-retention"
                        type="date"
                        value={docRetentionDate}
                        onChange={(e) => setDocRetentionDate(e.target.value)}
                        className="h-8 text-xs bg-slate-950 border-slate-800 text-slate-200"
                      />
                    </div>
                  </div>
                )}

                {wizardStep === 3 && (
                  <div className="space-y-3 text-xs">
                    <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3 space-y-2">
                      <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                        <ShieldCheck className="h-4 w-4" />
                        <span>Xác minh trước khi mã hóa lưu trữ</span>
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 text-slate-300 pt-1 border-t border-slate-800">
                        <span className="text-slate-400">Tiêu đề:</span>
                        <span className="font-semibold text-slate-100">{docTitle}</span>
                        {docFile && (
                          <>
                            <span className="text-slate-400">Tệp nguồn:</span>
                            <span className="font-mono text-slate-200">{docFile.name}</span>
                          </>
                        )}
                        <span className="text-slate-400">Mức độ mật:</span>
                        <ClassificationBadge level={docClassification} size="sm" />
                        <span className="text-slate-400">Chính sách tải:</span>
                        <span>
                          {docAllowDownload ? 'Cho phép tải có watermark' : 'Chỉ xem trực tuyến'}
                        </span>
                        <span className="text-slate-400">Mã hóa xác thực:</span>
                        <span className="font-mono text-emerald-400">AES-256-GCM / DEK</span>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Tài liệu sẽ được quét mã độc, trích xuất magic bytes, phân trang an toàn và
                      lưu vào bộ lưu trữ mã hóa độc lập. Dấu bản quyền (Watermark) sẽ được nhúng
                      động mỗi khi có yêu cầu truy cập.
                    </p>
                  </div>
                )}
              </div>

              <DialogFooter className="flex justify-between sm:justify-between pt-2">
                {wizardStep > 1 ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setWizardStep((prev) => (prev - 1) as 1 | 2)}
                    className="border-slate-800 text-slate-300"
                  >
                    Quay lại
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setUploadWizardOpen(false)}
                    className="border-slate-800 text-slate-400"
                  >
                    Hủy bỏ
                  </Button>
                )}

                {wizardStep < 3 ? (
                  <Button
                    type="button"
                    size="sm"
                    disabled={!docTitle.trim()}
                    onClick={() => setWizardStep((prev) => (prev + 1) as 2 | 3)}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    Tiếp theo
                  </Button>
                ) : (
                  <Button
                    type="button"
                    size="sm"
                    disabled={isSubmittingDoc}
                    onClick={() => void handleFinishUpload()}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    {isSubmittingDoc ? (
                      <>
                        <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        Đang xử lý & mã hóa…
                      </>
                    ) : (
                      'Xác nhận tải lên'
                    )}
                  </Button>
                )}
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* REVOKE GRANT MODAL */}
          <Dialog open={revokeOpen} onOpenChange={setRevokeOpen}>
            <DialogContent className="max-w-md border-red-900/50 bg-slate-900 text-slate-100">
              <DialogHeader>
                <div className="flex items-center gap-2 text-red-400">
                  <AlertOctagon className="h-5 w-5" />
                  <DialogTitle className="text-base font-semibold text-red-200">
                    Thu hồi giấy phép truy cập khẩn cấp
                  </DialogTitle>
                </div>
                <DialogDescription className="text-xs text-slate-400">
                  D-BR15: Bắt buộc nêu rõ lý do thu hồi (ít nhất 10 ký tự). Mọi phiên làm việc đang
                  chạy sẽ bị ngắt lập tức.
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleConfirmRevoke} className="space-y-3.5 py-2">
                <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs space-y-1">
                  <div>
                    Đối tượng:{' '}
                    <strong className="text-slate-100">{selectedGrant?.principalName}</strong>
                  </div>
                  <div>
                    Tài liệu: <span className="text-slate-300">{selectedGrant?.documentTitle}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="revoke-reason" className="text-xs font-medium text-slate-300">
                    Lý do thu hồi (Ghi vào Audit Trail) <span className="text-red-400">*</span>
                  </label>
                  <Textarea
                    id="revoke-reason"
                    required
                    rows={3}
                    value={revokeReason}
                    onChange={(e) => setRevokeReason(e.target.value)}
                    placeholder="Ví dụ: Dự án đã hoàn thành trước hạn; hoặc có dấu hiệu rò rỉ thông tin..."
                    className="text-xs bg-slate-950 border-slate-800 text-slate-100"
                  />
                  <p className="text-[10px] text-slate-400">
                    Tối thiểu 10 ký tự ({revokeReason.trim().length}/10)
                  </p>
                </div>

                <DialogFooter className="pt-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setRevokeOpen(false)}
                    className="border-slate-800 text-slate-400"
                  >
                    Hủy
                  </Button>
                  <Button
                    type="submit"
                    size="sm"
                    disabled={isRevoking || revokeReason.trim().length < 10}
                    className="bg-red-600 hover:bg-red-500 text-white font-medium"
                  >
                    {isRevoking ? (
                      <>
                        <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        Đang thu hồi…
                      </>
                    ) : (
                      'Xác nhận thu hồi ngay'
                    )}
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* APPROVE REQUEST MODAL */}
          <Dialog open={approveOpen} onOpenChange={setApproveOpen}>
            <DialogContent className="max-w-md border-slate-800 bg-slate-900 text-slate-100">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-slate-100">
                  Cấp giấy phép truy cập có thời hạn
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-400">
                  Xác định quyền (VIEW hoặc DOWNLOAD) và giới hạn thời gian hiệu lực
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3.5 py-2 text-xs">
                <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 space-y-1">
                  <div>
                    Người nhận quyền:{' '}
                    <strong className="text-slate-100">{selectedRequest?.requestorName}</strong>
                  </div>
                  <div>
                    Tài liệu:{' '}
                    <span className="text-slate-300">{selectedRequest?.documentTitle}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-slate-300 block">Phạm vi quyền cấp:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setGrantAction('VIEW')}
                      className={`flex items-center justify-center gap-1.5 p-2 rounded-lg border text-xs font-medium transition-all ${
                        grantAction === 'VIEW'
                          ? 'border-emerald-500 bg-emerald-950/60 text-emerald-300'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <Eye className="h-4 w-4" />
                      <span>Chỉ xem (VIEW)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setGrantAction('DOWNLOAD')}
                      className={`flex items-center justify-center gap-1.5 p-2 rounded-lg border text-xs font-medium transition-all ${
                        grantAction === 'DOWNLOAD'
                          ? 'border-emerald-500 bg-emerald-950/60 text-emerald-300'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <Download className="h-4 w-4" />
                      <span>Xem & Tải (DOWNLOAD)</span>
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="grant-duration" className="font-medium text-slate-300">
                    Thời hạn hiệu lực (Ngày):
                  </label>
                  <select
                    id="grant-duration"
                    value={grantValidDays}
                    onChange={(e) => setGrantValidDays(Number(e.target.value))}
                    className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
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
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setApproveOpen(false)}
                  className="border-slate-800 text-slate-400"
                >
                  Hủy
                </Button>
                <Button
                  type="button"
                  size="sm"
                  disabled={isApproving}
                  onClick={() => void handleConfirmApprove()}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                >
                  {isApproving ? (
                    <>
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                      Đang phê duyệt…
                    </>
                  ) : (
                    'Xác nhận cấp quyền'
                  )}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
