'use client';

import { useState, useEffect, useCallback, type FormEvent } from 'react';
import {
  Search,
  BookOpen,
  FileSearch,
  Eye,
  Download,
  Send,
  Clock,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  QrCode,
  ChevronLeft,
  ChevronRight,
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

interface DiscoverableDoc {
  id: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  classificationRank?: number | undefined;
  departmentName?: string | undefined;
  allowDownload: boolean;
  hasAccess?: boolean | undefined;
}

interface MyGrantedDoc {
  id: string;
  documentId: string;
  title: string;
  documentCode?: string | undefined;
  classificationCode: ClassificationCode;
  permissions: Array<'VIEW' | 'DOWNLOAD'>;
  validUntil: string;
  allowDownload: boolean;
}

interface MyRequestItem {
  id: string;
  documentTitle: string;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED';
  createdAt: string;
}

interface ReaderDocumentApiDto {
  id: string;
  title?: string;
  documentCode?: string;
  document_code?: string;
  classificationCode?: ClassificationCode;
  classification?: { code?: ClassificationCode; rank?: number };
  department?: { name?: string };
  allowDownload?: boolean;
}

interface ReaderGrantApiDto {
  id?: string;
  documentId?: string;
  title?: string;
  documentCode?: string;
  classificationCode?: ClassificationCode;
  document?: { title?: string; documentCode?: string; classificationCode?: ClassificationCode };
  permissions?: ('VIEW' | 'DOWNLOAD')[];
  validUntil?: string;
  allowDownload?: boolean;
}

export function ReaderWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('discover');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');

  const [discoverDocs, setDiscoverDocs] = useState<DiscoverableDoc[]>([]);
  const [myDocs, setMyDocs] = useState<MyGrantedDoc[]>([]);
  const [myRequests, setMyRequests] = useState<MyRequestItem[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Request Access Modal
  const [requestModalOpen, setRequestModalOpen] = useState(false);
  const [targetDoc, setTargetDoc] = useState<DiscoverableDoc | null>(null);
  const [requestedAction, setRequestedAction] = useState<'VIEW' | 'DOWNLOAD'>('VIEW');
  const [justification, setJustification] = useState('');
  const [isSubmittingRequest, setIsSubmittingRequest] = useState(false);

  // Sandbox Preview Modal
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<MyGrantedDoc | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewPdfUrl, setPreviewPdfUrl] = useState<string | null>(null);
  const [previewPage, setPreviewPage] = useState(1);
  const previewTotalPages = 3;
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);

  // Download Flow State
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);

  // Cancel Request State
  const [cancellingRequestId, setCancellingRequestId] = useState<string | null>(null);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [docsRes, myGrantsRes, requestsRes] = await Promise.all([
        apiClient<{ data: ReaderDocumentApiDto[] }>('/documents?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: ReaderGrantApiDto[] }>('/documents/my-grants?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: MyRequestItem[] }>('/access-requests?scope=my').catch(() => ({
          data: [],
        })),
      ]);

      const mappedDiscover: DiscoverableDoc[] = (docsRes.data || []).map((d) => ({
        id: d.id,
        title: d.title || 'Tài liệu không tên',
        documentCode: d.documentCode || d.document_code,
        classificationCode: (d.classification?.code ||
          d.classificationCode ||
          'CONFIDENTIAL') as ClassificationCode,
        classificationRank: d.classification?.rank ?? 3,
        departmentName: d.department?.name || 'Phòng Kỹ thuật',
        allowDownload: d.allowDownload ?? true,
        hasAccess: false,
      }));
      setDiscoverDocs(mappedDiscover);

      const mappedMy: MyGrantedDoc[] = (myGrantsRes.data || []).map((g) => ({
        id: g.id || g.documentId || 'grant-id',
        documentId: g.documentId || g.id || 'doc-id',
        title: g.title || g.document?.title || 'Tài liệu mật đã cấp quyền',
        documentCode: g.documentCode || g.document?.documentCode,
        classificationCode: (g.classificationCode ||
          g.document?.classificationCode ||
          'RESTRICTED') as ClassificationCode,
        permissions: g.permissions || ['VIEW'],
        validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
        allowDownload: g.allowDownload ?? true,
      }));

      setMyDocs(mappedMy);
      setMyRequests(requestsRes.data || []);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể tải danh mục tài liệu khám phá.');
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
  async function handleOpenPreview(doc: MyGrantedDoc) {
    setIsLoadingPreview(true);
    setErrorMessage(null);
    if (previewPdfUrl) {
      URL.revokeObjectURL(previewPdfUrl);
      setPreviewPdfUrl(null);
    }

    try {
      // Step 1: Request an access session from PEP
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      );

      setPreviewDoc(doc);
      setPreviewSessionId(sessionResult.sessionId);
      setPreviewPage(1);
      setPreviewOpen(true);

      // Step 2: Fetch the watermarked PDF preview stream directly from backend
      try {
        const pdfBlob = await apiDownload(
          `/documents/${doc.documentId}/preview?sessionId=${sessionResult.sessionId}`,
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
  async function handleDownloadWithTicket(doc: MyGrantedDoc) {
    if (!doc.allowDownload) {
      setErrorMessage('Tài liệu này thuộc diện cấm tải theo chính sách phân loại mật.');
      return;
    }

    setDownloadingDocId(doc.documentId);
    setErrorMessage(null);

    try {
      // Step 1: Create session
      const sessionResult = await apiClient<{ sessionId: string }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'DOWNLOAD' }),
        },
      );

      // Step 2: Create download ticket
      const ticketResult = await apiClient<{ ticket: string; expiresAt: string }>(
        `/documents/${doc.documentId}/download-ticket`,
        {
          method: 'POST',
          body: JSON.stringify({ sessionId: sessionResult.sessionId }),
        },
      );

      // Step 3: Trigger download
      const blob = await apiDownload(`/documents/download-with-ticket/${ticketResult.ticket}`);

      // Create browser link to save file
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

  // Submit Access Request
  async function handleSubmitRequest(e: FormEvent) {
    e.preventDefault();
    if (!targetDoc) return;

    if (justification.trim().length < 10) {
      setErrorMessage('Lý do đề xuất truy cập phải có ít nhất 10 ký tự.');
      return;
    }

    setIsSubmittingRequest(true);
    setErrorMessage(null);

    try {
      const created = await apiClient<MyRequestItem>('/access-requests', {
        method: 'POST',
        body: JSON.stringify({
          documentId: targetDoc.id,
          requestedAction,
          reason: justification.trim(),
        }),
      });

      setMessage(
        `Yêu cầu quyền ${requestedAction} tài liệu "${targetDoc.title}" đã được gửi đến chủ sở hữu để xét duyệt.`,
      );
      setRequestModalOpen(false);
      setTargetDoc(null);
      setJustification('');
      setMyRequests((prev) => [created, ...prev]);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể gửi yêu cầu cấp quyền.');
      }
    } finally {
      setIsSubmittingRequest(false);
    }
  }

  // UC15: Cancel Pending Access Request
  async function handleCancelRequest(requestId: string) {
    if (!confirm('Bạn có chắc chắn muốn hủy yêu cầu cấp quyền này không?')) {
      return;
    }
    setCancellingRequestId(requestId);
    setErrorMessage(null);
    try {
      await apiClient(`/access-requests/${requestId}/cancel`, {
        method: 'POST',
      });
      setMessage('Đã hủy yêu cầu cấp quyền thành công.');
      setMyRequests((prev) =>
        prev.map((r) => (r.id === requestId ? { ...r, status: 'CANCELLED' } : r)),
      );
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể hủy yêu cầu truy cập.');
      } else {
        setErrorMessage('Không thể hủy yêu cầu truy cập.');
      }
    } finally {
      setCancellingRequestId(null);
    }
  }

  // Filter discoverable documents
  const filteredDiscover = discoverDocs.filter((doc) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      doc.title.toLowerCase().includes(q) ||
      (doc.documentCode && doc.documentCode.toLowerCase().includes(q));
    const matchesClass =
      selectedClassification === 'ALL' || doc.classificationCode === selectedClassification;
    return matchesSearch && matchesClass;
  });

  return (
    <AuthGuard requiredRole="DOCUMENT_READER">
      <AppLayout>
        <div className="space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="info">Document Reader</Badge>
                <span className="text-xs text-[#717171]">Phân hệ Người đọc</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Khám phá & Đọc Tài liệu Mật
              </h1>
              <p className="text-xs text-[#717171]">
                Tìm kiếm danh mục tài liệu, gửi yêu cầu cấp quyền, xem trước an toàn và tải bản sao
                có watermark
              </p>
            </div>

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
            <TabsList className="grid w-full grid-cols-3 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger
                value="discover"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <FileSearch className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Khám phá danh mục</span>
                <span className="sm:hidden">Khám phá</span>
                <span className="text-[11px] opacity-80">({discoverDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger
                value="my-docs"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <BookOpen className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Tài liệu được xem</span>
                <span className="sm:hidden">Được xem</span>
                <span className="text-[11px] opacity-80">({myDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger
                value="my-requests"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Theo dõi yêu cầu</span>
                <span className="sm:hidden">Yêu cầu</span>
                <span className="text-[11px] opacity-80">({myRequests.length})</span>
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: DISCOVER */}
            <TabsContent value="discover" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Danh mục tài liệu tổ chức (Discover Search)
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Tìm kiếm toàn văn hỗ trợ tiếng Việt có dấu. Zero-IDOR: chỉ hiển thị metadata
                      được phép phát hiện
                    </CardDescription>
                  </div>
                  <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
                    <select
                      value={selectedClassification}
                      onChange={(e) => setSelectedClassification(e.target.value)}
                      className="h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                    >
                      <option value="ALL">Tất cả mức mật</option>
                      <option value="UNCLASSIFIED">Không mật</option>
                      <option value="RESTRICTED">Nội bộ</option>
                      <option value="CONFIDENTIAL">Mật</option>
                      <option value="SECRET">Tối mật</option>
                      <option value="TOP_SECRET">Tuyệt mật</option>
                    </select>

                    <div className="relative w-full sm:w-64">
                      <Search
                        className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-[#717171]"
                        aria-hidden="true"
                      />
                      <Input
                        type="text"
                        placeholder="Tìm kiếm tài liệu..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-10 h-10 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                      />
                    </div>
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
                          <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                          <TableHead className="text-xs text-[#717171]">Đơn vị chủ quản</TableHead>
                          <TableHead className="text-xs text-[#717171]">Chính sách tải</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Hành động
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDiscover.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Không tìm thấy tài liệu phù hợp với điều kiện tìm kiếm
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredDiscover.map((doc) => {
                            const isGranted = myDocs.some((m) => m.documentId === doc.id);
                            return (
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
                                <TableCell className="text-xs text-[#222222]">
                                  {doc.departmentName || 'Phòng Kỹ thuật'}
                                </TableCell>
                                <TableCell>
                                  {doc.allowDownload ? (
                                    <span className="text-[11px] text-[#008A05] font-medium">
                                      Cho phép tải
                                    </span>
                                  ) : (
                                    <span className="text-[11px] text-[#E07912] font-medium">
                                      Chỉ xem trực tuyến
                                    </span>
                                  )}
                                </TableCell>
                                <TableCell className="text-right">
                                  {isGranted ? (
                                    <InteractiveHoverButton
                                      size="sm"
                                      variant="primary"
                                      text="Xem tài liệu"
                                      icon={<Eye size={14} strokeWidth={1.75} aria-hidden="true" />}
                                      onClick={() => {
                                        const granted = myDocs.find((m) => m.documentId === doc.id);
                                        if (granted) void handleOpenPreview(granted);
                                      }}
                                    />
                                  ) : (
                                    <InteractiveHoverButton
                                      size="sm"
                                      variant="secondary"
                                      text="Yêu cầu quyền"
                                      icon={
                                        <Send size={14} strokeWidth={1.75} aria-hidden="true" />
                                      }
                                      onClick={() => {
                                        setTargetDoc(doc);
                                        setJustification('');
                                        setRequestModalOpen(true);
                                      }}
                                    />
                                  )}
                                </TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 2: MY ACCESSIBLE DOCUMENTS */}
            <TabsContent value="my-docs" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Tài liệu đã được cấp quyền truy cập
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Giấy phép còn hiệu lực theo thời gian quy định; xem trực tuyến hoặc tải về kèm
                    dấu bản quyền
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Tên tài liệu / Mã số
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Mức độ mật</TableHead>
                          <TableHead className="text-xs text-[#717171]">Quyền được cấp</TableHead>
                          <TableHead className="text-xs text-[#717171]">Hiệu lực đến</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Xem & Tải
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {myDocs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Bạn chưa có giấy phép truy cập nào còn hiệu lực
                            </TableCell>
                          </TableRow>
                        ) : (
                          myDocs.map((doc) => {
                            const canDownload =
                              doc.permissions.includes('DOWNLOAD') && doc.allowDownload;
                            const isDownloading = downloadingDocId === doc.documentId;

                            return (
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
                                  <div className="flex gap-1">
                                    {doc.permissions.map((p) => (
                                      <Badge key={p} variant="secondary">
                                        {p}
                                      </Badge>
                                    ))}
                                  </div>
                                </TableCell>
                                <TableCell className="text-xs font-bold text-amber-500">
                                  {new Date(doc.validUntil).toLocaleDateString('vi-VN')}
                                </TableCell>
                                <TableCell className="text-right space-x-1">
                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="primary"
                                    text="Xem Sandbox"
                                    icon={<Eye size={14} strokeWidth={1.75} aria-hidden="true" />}
                                    onClick={() => void handleOpenPreview(doc)}
                                  />

                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="secondary"
                                    text="Tải bản sao"
                                    icon={
                                      <Download size={14} strokeWidth={1.75} aria-hidden="true" />
                                    }
                                    disabled={!canDownload || isDownloading}
                                    isLoading={isDownloading}
                                    onClick={() => void handleDownloadWithTicket(doc)}
                                    title={
                                      !canDownload
                                        ? 'Chính sách mức mật hoặc giấy phép không cho phép tải về'
                                        : 'Tải bản sao có watermark bảo mật'
                                    }
                                  />
                                </TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 3: MY REQUESTS */}
            <TabsContent value="my-requests" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Trạng thái yêu cầu cấp quyền cá nhân
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Theo dõi tiến độ phê duyệt từ các chủ sở hữu tài liệu
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Tài liệu mục tiêu
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Quyền yêu cầu</TableHead>
                          <TableHead className="text-xs text-[#717171]">Thời gian gửi</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái xử lý</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Thao tác
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {myRequests.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Bạn chưa gửi yêu cầu cấp quyền nào
                            </TableCell>
                          </TableRow>
                        ) : (
                          myRequests.map((req) => (
                            <TableRow
                              key={req.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell className="font-semibold text-xs text-[#222222]">
                                {req.documentTitle}
                              </TableCell>
                              <TableCell>
                                <Badge variant="secondary">{req.requestedAction}</Badge>
                              </TableCell>
                              <TableCell className="text-xs text-[#717171] font-bold">
                                {new Date(req.createdAt).toLocaleDateString('vi-VN')}
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={
                                    req.status === 'PENDING'
                                      ? 'warning'
                                      : req.status === 'APPROVED'
                                        ? 'success'
                                        : req.status === 'CANCELLED'
                                          ? 'neutral'
                                          : 'destructive'
                                  }
                                >
                                  {req.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                {req.status === 'PENDING' && (
                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="secondary"
                                    text="Hủy yêu cầu"
                                    onClick={() => void handleCancelRequest(req.id)}
                                    isLoading={cancellingRequestId === req.id}
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
          </Tabs>

          {/* REQUEST ACCESS MODAL */}
          <Dialog open={requestModalOpen} onOpenChange={setRequestModalOpen}>
            <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Gửi yêu cầu cấp quyền truy cập tài liệu
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Nêu rõ căn cứ nghiệp vụ để chủ sở hữu tài liệu và hệ thống PDP phê duyệt
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleSubmitRequest} className="space-y-3.5 py-2 text-xs">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
                  <div className="text-[#717171]">Tài liệu yêu cầu:</div>
                  <div className="font-semibold text-[#222222]">{targetDoc?.title}</div>
                  {targetDoc && (
                    <div className="pt-1">
                      <ClassificationBadge level={targetDoc.classificationCode} size="sm" />
                    </div>
                  )}
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-[#222222] block">Mức quyền yêu cầu:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setRequestedAction('VIEW')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                        requestedAction === 'VIEW'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                      }`}
                    >
                      <Eye className="h-4 w-4" />
                      <span>Xem trực tuyến (VIEW)</span>
                    </button>
                    <button
                      type="button"
                      disabled={!targetDoc?.allowDownload}
                      onClick={() => setRequestedAction('DOWNLOAD')}
                      className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-[40px] border text-xs font-semibold transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer ${
                        requestedAction === 'DOWNLOAD'
                          ? 'border-[#FF385C] bg-[#FF385C] text-white shadow-xs'
                          : 'border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:border-[#dddddd] hover:bg-[#f7f7f7]'
                      } disabled:opacity-40 disabled:cursor-not-allowed`}
                    >
                      <Download className="h-4 w-4" />
                      <span>Xem & Tải bản sao</span>
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="req-justification" className="font-medium text-[#222222]">
                    Căn cứ nghiệp vụ / Lý do đề xuất <span className="text-red-400">*</span>
                  </label>
                  <Textarea
                    id="req-justification"
                    required
                    rows={3}
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    placeholder="Mô tả nhiệm vụ hoặc dự án cụ thể cần đối chiếu thông tin này..."
                    className="text-xs bg-[#f7f7f7] border-[#ebebeb] text-[#222222]"
                  />
                  <p className="text-[10px] text-[#717171]">
                    Tối thiểu 10 ký tự ({justification.trim().length}/10)
                  </p>
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setRequestModalOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="primary"
                    size="sm"
                    text="Gửi yêu cầu"
                    disabled={isSubmittingRequest || justification.trim().length < 10}
                    isLoading={isSubmittingRequest}
                  />
                </DialogFooter>
              </form>
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
                          {user?.fullName || 'NGUYEN VAN A'} · {user?.username}
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
                      <span>Phân hệ Reader · Controlled Delivery</span>
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
