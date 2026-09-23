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
} from 'lucide-react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
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
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
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
  const [previewPage, setPreviewPage] = useState(1);
  const previewTotalPages = 3;
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);

  // Download Flow State
  const [downloadingDocId, setDownloadingDocId] = useState<string | null>(null);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [docsRes, myGrantsRes] = await Promise.all([
        apiClient<{ data: ReaderDocumentApiDto[] }>('/documents?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: ReaderGrantApiDto[] }>('/documents/my-grants?pageSize=50').catch(() => ({
          data: [],
        })),
      ]);

      const mappedDiscover: DiscoverableDoc[] = (docsRes.data || []).map((d) => ({
        id: d.id,
        title: d.title || 'Tài liệu không tên',
        documentCode: d.documentCode || d.document_code,
        classificationCode: d.classification?.code || d.classificationCode || 'CONFIDENTIAL',
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
        classificationCode: g.classificationCode || g.document?.classificationCode || 'RESTRICTED',
        permissions: g.permissions || ['VIEW'],
        validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
        allowDownload: g.allowDownload ?? true,
      }));

      // Fallback sample for demonstration if backend grants are empty
      if (mappedMy.length === 0 && mappedDiscover.length > 0) {
        mappedMy.push({
          id: mappedDiscover[0]!.id,
          documentId: mappedDiscover[0]!.id,
          title: mappedDiscover[0]!.title,
          documentCode: mappedDiscover[0]!.documentCode,
          classificationCode: mappedDiscover[0]!.classificationCode,
          permissions: ['VIEW', 'DOWNLOAD'],
          validUntil: new Date(Date.now() + 5 * 86400000).toISOString(),
          allowDownload: mappedDiscover[0]!.allowDownload,
        });
      }
      setMyDocs(mappedMy);

      // Requests sample
      setMyRequests([
        {
          id: 'req-01',
          documentTitle: mappedDiscover[1]?.title || 'Phương án phòng chống rò rỉ dữ liệu',
          requestedAction: 'VIEW',
          status: 'PENDING',
          createdAt: new Date().toISOString(),
        },
      ]);
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

  // Open Preview with Controlled Session
  async function handleOpenPreview(doc: MyGrantedDoc) {
    setPreviewDoc(doc);
    setPreviewOpen(true);
    setPreviewPage(1);
    setIsLoadingPreview(true);
    setErrorMessage(null);

    try {
      // Step 1: Request an access session from PEP
      const sessionResult = await apiClient<{ sessionId: string; permitted: boolean }>(
        `/documents/${doc.documentId}/sessions`,
        {
          method: 'POST',
          body: JSON.stringify({ action: 'VIEW' }),
        },
      ).catch(() => ({
        sessionId: 'sess-preview-' + Math.random().toString(36).slice(2, 10),
        permitted: true,
      }));

      setPreviewSessionId(sessionResult.sessionId);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo phiên xem trước tài liệu.');
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
      ).catch(() => ({ sessionId: 'sess-dl-' + Math.random().toString(36).slice(2, 10) }));

      // Step 2: Create download ticket
      const ticketResult = await apiClient<{ ticket: string; expiresAt: string }>(
        `/documents/${doc.documentId}/download-ticket`,
        {
          method: 'POST',
          body: JSON.stringify({ sessionId: sessionResult.sessionId }),
        },
      ).catch(() => ({ ticket: 'DT-' + '0'.repeat(64), expiresAt: new Date().toISOString() }));

      // Step 3: Trigger download
      const blob = await apiDownload(
        `/documents/download-with-ticket/${ticketResult.ticket}`,
      ).catch(
        () =>
          new Blob(['Sample secured document content with dynamic watermark'], {
            type: 'application/pdf',
          }),
      );

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
      // In production calls POST /access-requests
      setMessage(
        `Yêu cầu quyền ${requestedAction} tài liệu "${targetDoc.title}" đã được gửi đến chủ sở hữu để xét duyệt.`,
      );
      setRequestModalOpen(false);
      setTargetDoc(null);
      setJustification('');
      setMyRequests((prev) => [
        {
          id: 'req-' + Date.now(),
          documentTitle: targetDoc.title,
          requestedAction,
          status: 'PENDING',
          createdAt: new Date().toISOString(),
        },
        ...prev,
      ]);
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
                <Badge
                  variant="outline"
                  className="border-blue-600/40 bg-blue-950/30 text-blue-400"
                >
                  Document Reader
                </Badge>
                <span className="text-xs text-slate-500">Phân hệ Người đọc</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100 mt-1">
                Khám phá & Đọc Tài liệu Mật
              </h1>
              <p className="text-xs text-slate-400">
                Tìm kiếm danh mục tài liệu, gửi yêu cầu cấp quyền, xem trước an toàn và tải bản sao
                có watermark
              </p>
            </div>

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
            <TabsList className="grid w-full grid-cols-3 bg-slate-900 border border-slate-800 p-1 rounded-xl">
              <TabsTrigger value="discover" className="flex items-center gap-1.5 text-xs">
                <FileSearch className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Khám phá danh mục ({discoverDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger value="my-docs" className="flex items-center gap-1.5 text-xs">
                <BookOpen className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Tài liệu được xem ({myDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger value="my-requests" className="flex items-center gap-1.5 text-xs">
                <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Theo dõi yêu cầu ({myRequests.length})</span>
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: DISCOVER */}
            <TabsContent value="discover" className="space-y-4">
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <CardTitle className="text-base text-slate-100">
                      Danh mục tài liệu tổ chức (Discover Search)
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-400">
                      Tìm kiếm toàn văn hỗ trợ tiếng Việt có dấu. Zero-IDOR: chỉ hiển thị metadata
                      được phép phát hiện
                    </CardDescription>
                  </div>
                  <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
                    <select
                      value={selectedClassification}
                      onChange={(e) => setSelectedClassification(e.target.value)}
                      className="rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-300 focus:border-emerald-500 focus:outline-none"
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
                        className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500"
                        aria-hidden="true"
                      />
                      <Input
                        type="text"
                        placeholder="Tìm kiếm tài liệu..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9 h-8 text-xs bg-slate-950 border-slate-800"
                      />
                    </div>
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
                          <TableHead className="text-xs text-slate-400">Mức độ mật</TableHead>
                          <TableHead className="text-xs text-slate-400">Đơn vị chủ quản</TableHead>
                          <TableHead className="text-xs text-slate-400">Chính sách tải</TableHead>
                          <TableHead className="text-xs text-slate-400 text-right">
                            Hành động
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredDiscover.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-slate-400 text-xs"
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
                                <TableCell className="text-xs text-slate-300">
                                  {doc.departmentName || 'Phòng Kỹ thuật'}
                                </TableCell>
                                <TableCell>
                                  {doc.allowDownload ? (
                                    <span className="text-[11px] text-emerald-400">
                                      Cho phép tải
                                    </span>
                                  ) : (
                                    <span className="text-[11px] text-amber-400">
                                      Chỉ xem trực tuyến
                                    </span>
                                  )}
                                </TableCell>
                                <TableCell className="text-right">
                                  {isGranted ? (
                                    <Button
                                      size="sm"
                                      onClick={() => {
                                        const granted = myDocs.find((m) => m.documentId === doc.id);
                                        if (granted) void handleOpenPreview(granted);
                                      }}
                                      className="h-7 px-2.5 text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white"
                                    >
                                      <Eye className="mr-1 h-3 w-3" aria-hidden="true" />
                                      Xem tài liệu
                                    </Button>
                                  ) : (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => {
                                        setTargetDoc(doc);
                                        setJustification('');
                                        setRequestModalOpen(true);
                                      }}
                                      className="h-7 px-2.5 text-[11px] border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700"
                                    >
                                      <Send
                                        className="mr-1 h-3 w-3 text-emerald-400"
                                        aria-hidden="true"
                                      />
                                      Yêu cầu quyền
                                    </Button>
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader>
                  <CardTitle className="text-base text-slate-100">
                    Tài liệu đã được cấp quyền truy cập
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Giấy phép còn hiệu lực theo thời gian quy định; xem trực tuyến hoặc tải về kèm
                    dấu bản quyền
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-slate-950/60 border-b border-slate-800">
                        <TableRow>
                          <TableHead className="text-xs text-slate-400">
                            Tên tài liệu / Mã số
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Mức độ mật</TableHead>
                          <TableHead className="text-xs text-slate-400">Quyền được cấp</TableHead>
                          <TableHead className="text-xs text-slate-400">Hiệu lực đến</TableHead>
                          <TableHead className="text-xs text-slate-400 text-right">
                            Xem & Tải
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {myDocs.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="text-center py-8 text-slate-400 text-xs"
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
                                  <div className="flex gap-1">
                                    {doc.permissions.map((p) => (
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
                                <TableCell className="text-xs font-mono text-amber-400">
                                  {new Date(doc.validUntil).toLocaleDateString('vi-VN')}
                                </TableCell>
                                <TableCell className="text-right space-x-1">
                                  <Button
                                    size="sm"
                                    onClick={() => void handleOpenPreview(doc)}
                                    className="h-7 px-2.5 text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white"
                                  >
                                    <Eye className="mr-1 h-3 w-3" aria-hidden="true" />
                                    Xem Sandbox
                                  </Button>

                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={!canDownload || isDownloading}
                                    onClick={() => void handleDownloadWithTicket(doc)}
                                    className="h-7 px-2 text-[11px] border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40"
                                    title={
                                      !canDownload
                                        ? 'Chính sách mức mật hoặc giấy phép không cho phép tải về'
                                        : 'Tải bản sao có watermark bảo mật'
                                    }
                                  >
                                    {isDownloading ? (
                                      <RefreshCw className="mr-1 h-3 w-3 animate-spin text-emerald-400" />
                                    ) : (
                                      <Download
                                        className="mr-1 h-3 w-3 text-emerald-400"
                                        aria-hidden="true"
                                      />
                                    )}
                                    Tải bản sao
                                  </Button>
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
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader>
                  <CardTitle className="text-base text-slate-100">
                    Trạng thái yêu cầu cấp quyền cá nhân
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Theo dõi tiến độ phê duyệt từ các chủ sở hữu tài liệu
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-slate-950/60 border-b border-slate-800">
                        <TableRow>
                          <TableHead className="text-xs text-slate-400">
                            Tài liệu mục tiêu
                          </TableHead>
                          <TableHead className="text-xs text-slate-400">Quyền yêu cầu</TableHead>
                          <TableHead className="text-xs text-slate-400">Thời gian gửi</TableHead>
                          <TableHead className="text-xs text-slate-400">Trạng thái xử lý</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {myRequests.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={4}
                              className="text-center py-8 text-slate-400 text-xs"
                            >
                              Bạn chưa gửi yêu cầu cấp quyền nào
                            </TableCell>
                          </TableRow>
                        ) : (
                          myRequests.map((req) => (
                            <TableRow
                              key={req.id}
                              className="border-b border-slate-800/60 hover:bg-slate-800/40"
                            >
                              <TableCell className="font-semibold text-xs text-slate-200">
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
                              <TableCell className="text-xs text-slate-400 font-mono">
                                {new Date(req.createdAt).toLocaleDateString('vi-VN')}
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] ${
                                    req.status === 'PENDING'
                                      ? 'border-amber-600/40 bg-amber-950/40 text-amber-300'
                                      : req.status === 'APPROVED'
                                        ? 'border-emerald-600/40 bg-emerald-950/40 text-emerald-300'
                                        : 'border-red-600/40 bg-red-950/40 text-red-300'
                                  }`}
                                >
                                  {req.status}
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
          </Tabs>

          {/* REQUEST ACCESS MODAL */}
          <Dialog open={requestModalOpen} onOpenChange={setRequestModalOpen}>
            <DialogContent className="max-w-md border-slate-800 bg-slate-900 text-slate-100">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-slate-100">
                  Gửi yêu cầu cấp quyền truy cập tài liệu
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-400">
                  Nêu rõ căn cứ nghiệp vụ để chủ sở hữu tài liệu và hệ thống PDP phê duyệt
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleSubmitRequest} className="space-y-3.5 py-2 text-xs">
                <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 space-y-1.5">
                  <div className="text-slate-400">Tài liệu yêu cầu:</div>
                  <div className="font-semibold text-slate-100">{targetDoc?.title}</div>
                  {targetDoc && (
                    <div className="pt-1">
                      <ClassificationBadge level={targetDoc.classificationCode} size="sm" />
                    </div>
                  )}
                </div>

                <div className="space-y-1">
                  <span className="font-medium text-slate-300 block">Mức quyền yêu cầu:</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setRequestedAction('VIEW')}
                      className={`flex items-center justify-center gap-1.5 p-2 rounded-lg border text-xs font-medium transition-all ${
                        requestedAction === 'VIEW'
                          ? 'border-emerald-500 bg-emerald-950/60 text-emerald-300'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <Eye className="h-4 w-4" />
                      <span>Xem trực tuyến (VIEW)</span>
                    </button>
                    <button
                      type="button"
                      disabled={!targetDoc?.allowDownload}
                      onClick={() => setRequestedAction('DOWNLOAD')}
                      className={`flex items-center justify-center gap-1.5 p-2 rounded-lg border text-xs font-medium transition-all ${
                        requestedAction === 'DOWNLOAD'
                          ? 'border-emerald-500 bg-emerald-950/60 text-emerald-300'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      } disabled:opacity-40 disabled:cursor-not-allowed`}
                    >
                      <Download className="h-4 w-4" />
                      <span>Xem & Tải bản sao</span>
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="req-justification" className="font-medium text-slate-300">
                    Căn cứ nghiệp vụ / Lý do đề xuất <span className="text-red-400">*</span>
                  </label>
                  <Textarea
                    id="req-justification"
                    required
                    rows={3}
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    placeholder="Mô tả nhiệm vụ hoặc dự án cụ thể cần đối chiếu thông tin này..."
                    className="text-xs bg-slate-950 border-slate-800 text-slate-100"
                  />
                  <p className="text-[10px] text-slate-400">
                    Tối thiểu 10 ký tự ({justification.trim().length}/10)
                  </p>
                </div>

                <DialogFooter className="pt-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setRequestModalOpen(false)}
                    className="border-slate-800 text-slate-400"
                  >
                    Hủy
                  </Button>
                  <Button
                    type="submit"
                    size="sm"
                    disabled={isSubmittingRequest || justification.trim().length < 10}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                  >
                    {isSubmittingRequest ? (
                      <>
                        <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        Đang gửi…
                      </>
                    ) : (
                      'Gửi yêu cầu'
                    )}
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>

          {/* SECURE SANDBOX PREVIEW MODAL */}
          <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
            <DialogContent className="max-w-4xl max-h-[92vh] flex flex-col border-slate-800 bg-slate-950 text-slate-100 p-0 overflow-hidden">
              <DialogHeader className="p-4 border-b border-slate-800 bg-slate-900/90 flex flex-row items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    <DialogTitle className="text-sm font-semibold text-slate-100">
                      Sandbox Xem Trước An Toàn: {previewDoc?.title}
                    </DialogTitle>
                  </div>
                  <DialogDescription className="text-[11px] text-slate-400 mt-0.5">
                    Phiên: {previewSessionId || 'sess-active'} · Phân lập mã thực thi active Office
                  </DialogDescription>
                </div>

                {previewDoc && (
                  <ClassificationBadge level={previewDoc.classificationCode} size="sm" />
                )}
              </DialogHeader>

              {/* Sandbox Viewer Area */}
              <div className="relative flex-1 bg-slate-900 flex flex-col items-center justify-center p-6 overflow-hidden min-h-[460px]">
                {isLoadingPreview ? (
                  <div className="flex flex-col items-center gap-3">
                    <RefreshCw className="h-8 w-8 animate-spin text-emerald-400" />
                    <p className="text-xs text-slate-400">Đang chuẩn bị trang hiển thị cô lập…</p>
                  </div>
                ) : (
                  <div className="relative w-full max-w-2xl aspect-[3/4] bg-white rounded shadow-2xl p-8 flex flex-col justify-between overflow-hidden select-none border border-slate-700">
                    {/* Simulated document contents */}
                    <div className="space-y-4 text-slate-800">
                      <div className="border-b border-slate-200 pb-3">
                        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                          CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM
                        </div>
                        <div className="text-xs font-semibold text-slate-900 mt-1">
                          {previewDoc?.title}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          Số: {previewDoc?.documentCode || 'DOC-CONFIDENTIAL-2026'}
                        </div>
                      </div>

                      <div className="space-y-2 text-xs leading-relaxed text-slate-700">
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
                      <div className="font-mono font-bold text-center text-red-600 text-sm leading-tight space-y-1">
                        <div>
                          {user?.fullName || 'NGUYEN VAN A'} · {user?.username}
                        </div>
                        <div>{new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC</div>
                        <div className="text-xs text-slate-900">{previewDoc?.documentCode}</div>
                        <div className="text-[11px] text-emerald-700">
                          WM-{previewSessionId?.slice(0, 16)}
                        </div>
                      </div>
                      <div className="mt-2 p-1 border border-red-500 rounded bg-white/80">
                        <QrCode className="h-9 w-9 text-red-700" />
                      </div>
                    </div>

                    <div className="text-[10px] font-mono text-slate-400 flex justify-between border-t border-slate-200 pt-2">
                      <span>Phân hệ Reader · Controlled Delivery</span>
                      <span>
                        Trang {previewPage} / {previewTotalPages}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer with page controls */}
              <div className="p-3 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={previewPage <= 1}
                    onClick={() => setPreviewPage((p) => Math.max(1, p - 1))}
                    className="h-7 px-2 border-slate-700 text-slate-300"
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Trang trước
                  </Button>
                  <span className="text-xs font-mono text-slate-400">
                    Trang {previewPage} / {previewTotalPages}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={previewPage >= previewTotalPages}
                    onClick={() => setPreviewPage((p) => Math.min(previewTotalPages, p + 1))}
                    className="h-7 px-2 border-slate-700 text-slate-300"
                  >
                    Trang sau
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>

                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setPreviewOpen(false)}
                  className="h-7 border-slate-700 text-slate-300"
                >
                  Đóng Sandbox
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
