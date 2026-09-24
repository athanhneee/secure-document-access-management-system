'use client';

import { useState, useEffect, useCallback, type FormEvent } from 'react';
import {
  AlertOctagon,
  Search,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  QrCode,
  FileText,
  Check,
  Play,
  Settings,
  FileCheck,
  Laptop,
  Network,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Activity,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
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

interface SecurityAlertItem {
  id: string;
  ruleCode: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserId?: string | undefined;
  detectedUserName?: string | undefined;
  documentId?: string | undefined;
  ipAddress?: string | undefined;
  detectedAt: string;
  details?: Record<string, unknown> | undefined;
  notes?: Array<{ note: string; authorName: string; createdAt: string }> | undefined;
}

interface IncidentItem {
  id: string;
  title: string;
  summary: string;
  status: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string | undefined;
  createdAt: string;
  actions?:
    | Array<{
        id: string;
        actionType: string;
        recommendation: string;
        isCompleted: boolean;
      }>
    | undefined;
}

interface DetectionRuleItem {
  code: string;
  name: string;
  severity: string;
  threshold: number;
  windowMinutes: number;
  isEnabled?: boolean | undefined;
}

interface AlertApiDto {
  id?: string;
  ruleCode?: string;
  alert_type?: string;
  title?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserId?: string;
  detectedUser?: { fullName?: string };
  documentId?: string;
  ipAddress?: string;
  detectedAt?: string;
  details?: Record<string, unknown>;
}

interface IncidentApiDto {
  id?: string;
  title?: string;
  summary?: string;
  status?: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string;
  createdAt?: string;
  actions?: Array<{
    id: string;
    actionType: string;
    recommendation: string;
    isCompleted: boolean;
  }>;
}

interface WatermarkVerifyDto {
  verified?: boolean;
  documentTitle?: string;
  documentCode?: string;
  recipientName?: string;
  employeeCode?: string;
  sessionId?: string;
  generatedAtUtc?: string;
  generatedAt?: string;
  classificationName?: string;
  document?: { title?: string; documentCode?: string };
  user?: { fullName?: string; employeeCode?: string };
  session?: { id?: string };
}

interface WatermarkProvenance {
  verified: boolean;
  documentTitle: string;
  documentCode: string;
  recipientName: string;
  employeeCode: string;
  sessionId: string;
  generatedAtUtc: string;
  classificationName: string;
}

interface DocumentSessionItem {
  id: string;
  accessGrantId: string;
  username: string;
  fullName: string;
  documentTitle: string;
  documentCode: string;
  versionNo: number;
  ipAddress: string;
  status: string;
  startedAt: string;
  lastActivityAt: string;
}

export function SecurityWorkspace() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRuleItem[]>([]);
  const [documentSessions, setDocumentSessions] = useState<DocumentSessionItem[]>([]);
  const [terminatingSessionId, setTerminatingSessionId] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Watermark trace tool state
  const [wmInputToken, setWmInputToken] = useState('');
  const [wmTraceResult, setWmTraceResult] = useState<WatermarkProvenance | null>(null);
  const [isTracingWm, setIsTracingWm] = useState(false);

  // Alert Detail / Action Modal
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlertItem | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [newStatus, setNewStatus] = useState<SecurityAlertItem['status']>('INVESTIGATING');
  const [resolutionNote, setResolutionNote] = useState('');
  const [investigationNote, setInvestigationNote] = useState('');
  const [isUpdatingAlert, setIsUpdatingAlert] = useState(false);

  // Create Incident Modal State
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);
  const [incTitle, setIncTitle] = useState('');
  const [incSummary, setIncSummary] = useState('');
  const [isCreatingInc, setIsCreatingInc] = useState(false);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [alertsRes, incRes, rulesRes, sessionsRes] = await Promise.all([
        apiClient<{ data: AlertApiDto[] }>('/security-alerts?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: IncidentApiDto[] }>('/incidents?pageSize=50').catch(() => ({ data: [] })),
        apiClient<DetectionRuleItem[]>('/security-detection/rules').catch(() => []),
        apiClient<{ data: DocumentSessionItem[] }>('/access-sessions').catch(() => ({ data: [] })),
      ]);

      setDocumentSessions(sessionsRes.data || []);

      const mappedAlerts: SecurityAlertItem[] = (alertsRes.data || []).map((a) => ({
        id: a.id || 'alt-id',
        ruleCode: a.ruleCode || a.alert_type || 'ANOMALY_DETECTION',
        title: a.title || 'Phát hiện hành vi bất thường',
        severity: a.severity || 'HIGH',
        status: a.status || 'OPEN',
        detectedUserId: a.detectedUserId,
        detectedUserName: a.detectedUser?.fullName || 'Người dùng ID: ' + (a.detectedUserId || '2'),
        documentId: a.documentId,
        ipAddress: a.ipAddress || '192.168.1.105',
        detectedAt: a.detectedAt || new Date().toISOString(),
        details: a.details,
      }));

      setAlerts(mappedAlerts);

      const mappedIncidents: IncidentItem[] = (incRes.data || []).map((inc) => ({
        id: inc.id || 'inc-id',
        title: inc.title || 'Báo cáo sự cố bảo mật',
        summary: inc.summary || '',
        status: inc.status || 'DRAFT',
        severity: inc.severity || 'HIGH',
        createdAt: inc.createdAt || new Date().toISOString(),
        actions: inc.actions || [],
      }));
      setIncidents(mappedIncidents);

      setDetectionRules(Array.isArray(rulesRes) ? rulesRes : []);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể tải dữ liệu an ninh thông tin.');
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

  // Handle Watermark Trace
  async function handleTraceWatermark(e: FormEvent) {
    e.preventDefault();
    if (!wmInputToken.trim()) return;

    setIsTracingWm(true);
    setErrorMessage(null);
    setWmTraceResult(null);

    try {
      const res = await apiClient<WatermarkVerifyDto>(
        `/watermarks/verify/${encodeURIComponent(wmInputToken.trim())}`,
      );

      setWmTraceResult({
        verified: res.verified ?? true,
        documentTitle: res.document?.title || res.documentTitle || 'Tài liệu mật điều tra',
        documentCode: res.document?.documentCode || res.documentCode || 'DOC-SECRET-001',
        recipientName: res.user?.fullName || res.recipientName || 'Người nhận xác minh',
        employeeCode: res.user?.employeeCode || res.employeeCode || 'EMP-TRACE',
        sessionId: res.session?.id || res.sessionId || 'sess-trace',
        generatedAtUtc: res.generatedAt || res.generatedAtUtc || new Date().toISOString(),
        classificationName: res.classificationName || 'CONFIDENTIAL',
      });
      setMessage('Đã hoàn tất đối soát chứng cứ dấu bản quyền.');
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Mã watermark không tồn tại hoặc không hợp lệ.');
      } else {
        setErrorMessage('Không thể đối soát mã watermark.');
      }
    } finally {
      setIsTracingWm(false);
    }
  }

  // Handle Alert Status Update
  async function handleUpdateAlertStatus() {
    if (!selectedAlert) return;
    if (
      (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') &&
      resolutionNote.trim().length < 5
    ) {
      setErrorMessage(
        'Cần ghi rõ ghi chú kết luận xử lý (ít nhất 5 ký tự) khi đóng hoặc đánh dấu false-positive.',
      );
      return;
    }

    setIsUpdatingAlert(true);
    setErrorMessage(null);

    try {
      await apiClient(`/security-alerts/${selectedAlert.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: newStatus,
          resolutionNote: resolutionNote.trim() || undefined,
        }),
      });

      if (investigationNote.trim()) {
        await apiClient(`/security-alerts/${selectedAlert.id}/notes`, {
          method: 'POST',
          body: JSON.stringify({ note: investigationNote.trim() }),
        });
      }

      setMessage(`Đã cập nhật trạng thái cảnh báo thành ${newStatus}.`);
      setAlertDetailOpen(false);
      setSelectedAlert(null);
      setResolutionNote('');
      setInvestigationNote('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cập nhật trạng thái cảnh báo.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật cảnh báo.');
      }
    } finally {
      setIsUpdatingAlert(false);
    }
  }

  // Handle Create Incident
  async function handleCreateIncident(e: FormEvent) {
    e.preventDefault();
    if (!incTitle.trim() || incSummary.trim().length < 10) {
      setErrorMessage('Tiêu đề và tóm tắt sự cố (ít nhất 10 ký tự) là bắt buộc.');
      return;
    }

    setIsCreatingInc(true);
    setErrorMessage(null);
    try {
      await apiClient('/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: incTitle.trim(),
          summary: incSummary.trim(),
        }),
      });

      setMessage('Đã khởi tạo hồ sơ báo cáo sự cố an ninh (trạng thái DRAFT).');
      setCreateIncidentOpen(false);
      setIncTitle('');
      setIncSummary('');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo báo cáo sự cố.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo sự cố.');
      }
    } finally {
      setIsCreatingInc(false);
    }
  }

  // Trigger Anomaly Detection Run
  async function handleRunDetection() {
    setIsLoading(true);
    try {
      await apiClient('/security-detection/run', {
        method: 'POST',
        body: JSON.stringify({ windowMinutes: 60 }),
      });
      setMessage('Đã kích hoạt quét phát hiện bất thường trên toàn bộ audit log 60 phút qua.');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể chạy quét bất thường.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  // Handle Terminate Session (UC22)
  async function handleTerminateSession(sessionId: string) {
    if (
      !confirm('Bạn có chắc chắn muốn ngắt kết nối phiên truy cập tài liệu này ngay lập tức không?')
    ) {
      return;
    }
    setTerminatingSessionId(sessionId);
    setErrorMessage(null);
    try {
      await apiClient(`/access-sessions/${sessionId}/terminate`, {
        method: 'POST',
      });
      setMessage('Đã ngắt phiên truy cập tài liệu thành công.');
      setDocumentSessions((prev) =>
        prev.map((s) => (s.id === sessionId ? { ...s, status: 'TERMINATED' } : s)),
      );
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể ngắt phiên truy cập.');
      } else {
        setErrorMessage('Không thể ngắt phiên truy cập.');
      }
    } finally {
      setTerminatingSessionId(null);
    }
  }

  const dlpAlerts = alerts.filter(
    (a) =>
      a.ruleCode === 'NETWORK_DLP_VIOLATION' ||
      a.ruleCode.includes('DLP') ||
      a.title?.toLowerCase().includes('dlp'),
  );

  return (
    <AuthGuard requiredRole="SECURITY_OFFICER">
      <AppLayout>
        <div className="space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="destructive">Security Officer</Badge>
                <span className="text-xs text-[#717171]">Phân hệ An ninh Thông tin</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Giám sát An ninh & Điều tra Sự cố
              </h1>
              <p className="text-xs text-[#717171]">
                Xử lý cảnh báo xâm phạm, điều tra provenance watermark, xử lý sự cố và luật phát
                hiện
              </p>
            </div>

            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                variant="secondary"
                size="sm"
                text="Làm mới"
                icon={<RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />}
                onClick={() => void refreshData()}
                disabled={isLoading}
              />
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Lập báo cáo sự cố"
                icon={<FileCheck size={14} />}
                onClick={() => setCreateIncidentOpen(true)}
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
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-6 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger value="alerts" className="flex items-center gap-1.5 text-xs">
                <AlertOctagon className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Cảnh báo ({alerts.length})</span>
              </TabsTrigger>
              <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                <QrCode className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Truy vết Watermark</span>
              </TabsTrigger>
              <TabsTrigger value="incidents" className="flex items-center gap-1.5 text-xs">
                <FileText className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Báo cáo sự cố ({incidents.length})</span>
              </TabsTrigger>
              <TabsTrigger value="sessions" className="flex items-center gap-1.5 text-xs">
                <Laptop className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  Phiên đọc ({documentSessions.filter((s) => s.status === 'ACTIVE').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="detection" className="flex items-center gap-1.5 text-xs">
                <Settings className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Luật phát hiện ({detectionRules.length})</span>
              </TabsTrigger>
              <TabsTrigger value="network-dlp" className="flex items-center gap-1.5 text-xs">
                <Network className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Network DLP ({dlpAlerts.length})</span>
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: SECURITY ALERTS */}
            <TabsContent value="alerts" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Hàng đợi cảnh báo bảo mật (Security Alerts)
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Phát hiện bất thường thời gian thực: tải ồ ạt, bị từ chối liên tục, ngoài giờ,
                    IP lạ
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">
                            Mức độ nghiêm trọng
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Loại cảnh báo / Tiêu đề
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Đối tượng phát hiện
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">Xử lý</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {alerts.map((alert) => (
                          <TableRow
                            key={alert.id}
                            className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                          >
                            <TableCell>
                              <Badge
                                variant={
                                  alert.severity === 'CRITICAL'
                                    ? 'destructive'
                                    : alert.severity === 'HIGH'
                                      ? 'warning'
                                      : 'info'
                                }
                              >
                                {alert.severity}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="font-semibold text-xs text-[#222222]">
                                {alert.title}
                              </div>
                              <div className="text-[11px] font-bold text-[#717171]">
                                {alert.ruleCode}
                              </div>
                            </TableCell>
                            <TableCell className="text-xs text-[#222222]">
                              {alert.detectedUserName || 'Chưa định danh'}
                            </TableCell>
                            <TableCell className="font-bold text-xs text-[#717171]">
                              {alert.ipAddress}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  alert.status === 'OPEN'
                                    ? 'destructive'
                                    : alert.status === 'INVESTIGATING'
                                      ? 'warning'
                                      : 'success'
                                }
                              >
                                {alert.status}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right">
                              <InteractiveHoverButton
                                size="sm"
                                variant="secondary"
                                text="Chi tiết"
                                icon={<Search size={14} />}
                                onClick={() => {
                                  setSelectedAlert(alert);
                                  setNewStatus(
                                    alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
                                  );
                                  setResolutionNote('');
                                  setInvestigationNote('');
                                  setAlertDetailOpen(true);
                                }}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 2: WATERMARK PROVENANCE LOOKUP */}
            <TabsContent value="watermark-trace" className="space-y-4">
              <div className="grid gap-6 md:grid-cols-2">
                <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                  <CardHeader>
                    <CardTitle className="text-base text-[#222222]">
                      Tra cứu dấu bản quyền (Watermark Forensic)
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      UC28: Nhập mã token trên tài liệu rò rỉ để đối chiếu xuất xứ, thời điểm và
                      người nhận
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4 text-xs">
                    <form onSubmit={handleTraceWatermark} className="space-y-3">
                      <div className="space-y-1">
                        <label htmlFor="wm-token-input" className="font-medium text-[#222222]">
                          Mã Token Watermark (Dạng WM-...)
                        </label>
                        <Input
                          id="wm-token-input"
                          value={wmInputToken}
                          onChange={(e) => setWmInputToken(e.target.value)}
                          placeholder="Ví dụ: WM-8f3a9b2c1e7d4410"
                          className="h-9 font-bold text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#008A05] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                        />
                      </div>

                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="md"
                        text="Đối soát xuất xứ tài liệu"
                        icon={<Search size={14} />}
                        isLoading={isTracingWm}
                        disabled={isTracingWm || !wmInputToken.trim()}
                        className="w-full"
                      />
                    </form>

                    <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-[#717171] text-[11px] leading-relaxed">
                      <p>
                        <strong>Nguyên lý:</strong> Mỗi lần người dùng bấm xem hoặc tải tài liệu, hệ
                        thống sinh ra một Watermark Instance gắn với phiên Access Session và
                        Document Version cụ thể.
                      </p>
                      <p>
                        Token được tạo ngẫu nhiên bằng CSPRNG, tuyệt đối không suy đoán được và liên
                        kết chặt chẽ vào nhật ký kiểm toán HMAC-SHA256.
                      </p>
                    </div>
                  </CardContent>
                </Card>

                {/* Trace Result Card */}
                <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col justify-between">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base text-[#222222]">
                      Kết quả đối soát bằng chứng
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Thông tin truy nguyên người chịu trách nhiệm phát tán
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex-1 flex flex-col justify-center text-xs">
                    {wmTraceResult ? (
                      <div className="space-y-3 rounded-[24px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                        <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                          <CheckCircle2 className="h-4 w-4" />
                          <span>Đối soát thành công · Bằng chứng hợp lệ</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[#222222]">
                          <span className="text-[#717171]">Tài liệu:</span>
                          <span className="font-semibold text-[#222222]">
                            {wmTraceResult.documentTitle}
                          </span>

                          <span className="text-[#717171]">Mã số tài liệu:</span>
                          <span className="font-bold text-[#222222]">
                            {wmTraceResult.documentCode}
                          </span>

                          <span className="text-[#717171]">Mức độ mật:</span>
                          <span className="font-semibold text-[#C13515]">
                            {wmTraceResult.classificationName}
                          </span>

                          <span className="text-[#717171]">Người nhận cấp quyền:</span>
                          <span className="font-semibold text-[#222222]">
                            {wmTraceResult.recipientName}
                          </span>

                          <span className="text-[#717171]">Mã nhân viên (EMP):</span>
                          <span className="font-bold text-[#008A05]">
                            {wmTraceResult.employeeCode}
                          </span>

                          <span className="text-[#717171]">Thời điểm tạo phiên:</span>
                          <span className="font-bold text-[#222222]">
                            {wmTraceResult.generatedAtUtc}
                          </span>

                          <span className="text-[#717171]">Session ID:</span>
                          <span className="font-bold text-[10px] text-[#717171]">
                            {wmTraceResult.sessionId}
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center text-center p-8 text-[#717171] space-y-2">
                        <QrCode className="h-10 w-10 text-[#b0b0b0]" />
                        <p>
                          Nhập mã token ở bên trái và bấm đối soát để hiển thị thông tin chứng cứ
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            {/* TAB 3: INCIDENT REPORTS */}
            <TabsContent value="incidents" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Báo cáo sự cố an ninh thông tin
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Hồ sơ sự cố, bằng chứng liên kết và hành động khắc phục (Corrective Actions)
                    </CardDescription>
                  </div>
                  <InteractiveHoverButton
                    size="sm"
                    variant="primary"
                    text="Tạo báo cáo mới"
                    icon={<FileCheck size={14} />}
                    onClick={() => setCreateIncidentOpen(true)}
                  />
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">Tiêu đề sự cố</TableHead>
                          <TableHead className="text-xs text-[#717171]">Tóm tắt tác động</TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Hành động khắc phục
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {incidents.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={4}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Chưa có hồ sơ sự cố an ninh nào được tạo
                            </TableCell>
                          </TableRow>
                        ) : (
                          incidents.map((inc) => (
                            <TableRow
                              key={inc.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell className="font-semibold text-xs text-[#222222]">
                                {inc.title}
                              </TableCell>
                              <TableCell className="text-xs text-[#222222] max-w-sm truncate">
                                {inc.summary}
                              </TableCell>
                              <TableCell className="text-xs text-[#222222]">
                                {inc.actions && inc.actions.length > 0 ? (
                                  <span className="text-[#008A05] font-medium">
                                    {inc.actions.filter((a) => a.isCompleted).length}/
                                    {inc.actions.length} hoàn tất
                                  </span>
                                ) : (
                                  <span className="text-[#717171]">Chưa có hành động</span>
                                )}
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant={
                                    inc.status === 'CLOSED'
                                      ? 'success'
                                      : inc.status === 'DRAFT'
                                        ? 'warning'
                                        : 'info'
                                  }
                                >
                                  {inc.status}
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

            {/* TAB 4: DETECTION RULES */}
            <TabsContent value="detection" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
                  <div>
                    <CardTitle className="text-base text-[#222222]">
                      Quy tắc phát hiện bất thường tự động
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Cấu hình ngưỡng số lần (threshold), cửa sổ thời gian (window) và thời gian hạ
                      nhiệt (cooldown)
                    </CardDescription>
                  </div>
                  <InteractiveHoverButton
                    size="sm"
                    variant="danger"
                    text="Kích hoạt quét toàn bộ ngay"
                    icon={<Play size={14} />}
                    onClick={() => void handleRunDetection()}
                  />
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">Mã quy tắc</TableHead>
                          <TableHead className="text-xs text-[#717171]">Tên quy tắc</TableHead>
                          <TableHead className="text-xs text-[#717171]">Mức nghiêm trọng</TableHead>
                          <TableHead className="text-xs text-[#717171]">
                            Ngưỡng (Threshold)
                          </TableHead>
                          <TableHead className="text-xs text-[#717171]">Cửa sổ (Phút)</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {detectionRules.map((r, i) => (
                          <TableRow
                            key={i}
                            className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                          >
                            <TableCell className="font-bold text-xs text-[#222222]">
                              {r.code}
                            </TableCell>
                            <TableCell className="font-semibold text-xs text-[#222222]">
                              {r.name}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  r.severity === 'CRITICAL'
                                    ? 'destructive'
                                    : r.severity === 'HIGH'
                                      ? 'warning'
                                      : 'info'
                                }
                              >
                                {r.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs font-bold text-[#222222]">
                              {r.threshold} lần
                            </TableCell>
                            <TableCell className="text-xs font-bold text-[#222222]">
                              {r.windowMinutes}m
                            </TableCell>
                            <TableCell>
                              <span className="flex items-center gap-1 text-[11px] text-[#008A05]">
                                <Check className="h-3 w-3" />
                                <span>Kích hoạt</span>
                              </span>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 5: ACTIVE DOCUMENT SESSIONS (UC22) */}
            <TabsContent value="sessions" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <CardTitle className="text-base text-[#222222]">
                    Phiên truy cập tài liệu đang hoạt động
                  </CardTitle>
                  <CardDescription className="text-xs text-[#717171]">
                    Giám sát các phiên đọc trực tuyến có nhúng watermark và thu hồi phiên truy cập
                    tức thời khi phát hiện bất thường
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                        <TableRow>
                          <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                          <TableHead className="text-xs text-[#717171]">Người dùng</TableHead>
                          <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                          <TableHead className="text-xs text-[#717171]">Bắt đầu lúc</TableHead>
                          <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                          <TableHead className="text-xs text-[#717171] text-right">
                            Thao tác
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {documentSessions.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={6}
                              className="text-center py-8 text-[#717171] text-xs"
                            >
                              Không có phiên truy cập tài liệu nào đang hoạt động
                            </TableCell>
                          </TableRow>
                        ) : (
                          documentSessions.map((sess) => (
                            <TableRow
                              key={sess.id}
                              className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                            >
                              <TableCell className="font-semibold text-xs text-[#222222]">
                                <div>{sess.documentTitle}</div>
                                <div className="text-[10px] text-[#717171] font-normal">
                                  {sess.documentCode} · v{sess.versionNo}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-[#222222]">
                                <div className="font-medium">{sess.fullName}</div>
                                <div className="text-[10px] text-[#717171]">{sess.username}</div>
                              </TableCell>
                              <TableCell className="text-xs font-mono text-[#717171]">
                                {sess.ipAddress}
                              </TableCell>
                              <TableCell className="text-xs text-[#717171]">
                                {new Date(sess.startedAt).toLocaleString('vi-VN')}
                              </TableCell>
                              <TableCell>
                                <Badge variant={sess.status === 'ACTIVE' ? 'success' : 'neutral'}>
                                  {sess.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                {sess.status === 'ACTIVE' && (
                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="destructive"
                                    text="Ngắt phiên"
                                    onClick={() => void handleTerminateSession(sess.id)}
                                    isLoading={terminatingSessionId === sess.id}
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

            {/* TAB 6: NETWORK DLP GATEWAY (RFC 3507 ICAP SERVER) */}
            <TabsContent value="network-dlp" className="space-y-4">
              <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                <CardHeader>
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div>
                      <CardTitle className="text-base text-[#222222] flex items-center gap-2">
                        <Network className="h-4 w-4 text-[#FF385C]" />
                        <span>
                          Cổng phòng chống thất thoát dữ liệu tầng mạng (Network DLP Gateway)
                        </span>
                      </CardTitle>
                      <CardDescription className="text-xs text-[#717171] mt-1">
                        Tích hợp máy chủ ICAP Server (RFC 3507) kiểm tra luồng dữ liệu ra ngoài
                        Internet (Egress Traffic) kết nối thiết bị biên (Squid, Symantec,
                        Forcepoint, F5)
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="success">ONLINE · TCP 1344</Badge>
                      <Badge variant="danger">BLOCK VIOLATIONS</Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Status Overview Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
                      <div className="flex items-center justify-between text-xs text-[#717171]">
                        <span>Giao thức mạng</span>
                        <Cpu className="h-3.5 w-3.5 text-[#008489]" />
                      </div>
                      <div className="text-sm font-bold text-[#222222]">ICAP/1.0 (RFC 3507)</div>
                      <p className="text-[11px] text-[#717171]">
                        Lắng nghe cổng TCP 1344 (IANA Standard)
                      </p>
                    </div>

                    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
                      <div className="flex items-center justify-between text-xs text-[#717171]">
                        <span>Cơ chế kiểm tra</span>
                        <Activity className="h-3.5 w-3.5 text-[#008A05]" />
                      </div>
                      <div className="text-sm font-bold text-[#222222]">RESPMOD & REQMOD</div>
                      <p className="text-[11px] text-[#717171]">
                        Hỗ trợ Preview Chunks & 204 No-Mod
                      </p>
                    </div>

                    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
                      <div className="flex items-center justify-between text-xs text-[#717171]">
                        <span>Chính sách phản hồi</span>
                        <ShieldAlert className="h-3.5 w-3.5 text-[#C13515]" />
                      </div>
                      <div className="text-sm font-bold text-[#C13515]">HTTP 403 Forbidden</div>
                      <p className="text-[11px] text-[#717171]">
                        Chặn luồng vi phạm kèm trang cảnh báo SDA
                      </p>
                    </div>

                    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
                      <div className="flex items-center justify-between text-xs text-[#717171]">
                        <span>Luồng sạch (Clean Pass)</span>
                        <ShieldCheck className="h-3.5 w-3.5 text-[#008A05]" />
                      </div>
                      <div className="text-sm font-bold text-[#008A05]">204 No modifications</div>
                      <p className="text-[11px] text-[#717171]">
                        Chuyển tiếp tức thì, không giữ buffer dữ liệu
                      </p>
                    </div>
                  </div>

                  {/* Policies Inspected */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
                      Các chính sách phân tích rò rỉ dữ liệu (Inspection Policies)
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[#222222]">
                            Nhãn phân loại mật quốc gia & doanh nghiệp
                          </span>
                          <Badge variant="danger">BẮT BUỘC</Badge>
                        </div>
                        <p className="text-[11px] text-[#717171]">
                          Quét nội dung chứa nhãn{' '}
                          <span className="font-mono font-medium">TUYỆT MẬT</span>,{' '}
                          <span className="font-mono font-medium">TỐI MẬT</span>,{' '}
                          <span className="font-mono font-medium">TOP SECRET</span>,{' '}
                          <span className="font-mono font-medium">STRICTLY CONFIDENTIAL</span> gửi
                          ra Internet.
                        </p>
                      </div>

                      <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[#222222]">
                            Thủy ấn số pháp chứng rò rỉ (Watermark Leak)
                          </span>
                          <Badge variant="primary">PHÁP CHỨNG</Badge>
                        </div>
                        <p className="text-[11px] text-[#717171]">
                          Phát hiện các mã token thủy ấn bí mật định dạng{' '}
                          <span className="font-mono font-medium">WM-[a-f0-9]{48}</span> bị người
                          dùng cố ý sao chép hoặc tuồn qua đường mạng biên.
                        </p>
                      </div>

                      <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[#222222]">
                            Khóa bí mật & Tokens truy cập (Secrets/Keys)
                          </span>
                          <Badge variant="warning">BẢO VỆ KHÓA</Badge>
                        </div>
                        <p className="text-[11px] text-[#717171]">
                          Ngăn chặn rò rỉ{' '}
                          <span className="font-mono font-medium">PEM RSA/EC Private Keys</span>,{' '}
                          <span className="font-mono font-medium">AWS Access Key (AKIA...)</span>,{' '}
                          <span className="font-mono font-medium">
                            GitHub Personal Access Token (ghp_...)
                          </span>
                          .
                        </p>
                      </div>

                      <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[#222222]">
                            Thẻ tài chính quốc tế & CCCD Việt Nam (PII)
                          </span>
                          <Badge variant="info">DỮ LIỆU CÁ NHÂN</Badge>
                        </div>
                        <p className="text-[11px] text-[#717171]">
                          Kiểm tra số thẻ Visa / MasterCard / Amex bằng{' '}
                          <span className="font-medium">thuật toán Luhn Checksum</span> và số Căn
                          cước công dân 12 chữ số theo quy chuẩn quốc gia.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* DLP Violations Table */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
                        Cảnh báo rò rỉ dữ liệu tầng mạng gần đây ({dlpAlerts.length})
                      </h3>
                      <span className="text-[11px] text-[#717171]">
                        Tự động đồng bộ từ sự kiện ICAP Gateway
                      </span>
                    </div>

                    <div className="overflow-x-auto rounded-[16px] border border-[#ebebeb]">
                      <Table>
                        <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                          <TableRow>
                            <TableHead className="text-xs text-[#717171]">Mức độ</TableHead>
                            <TableHead className="text-xs text-[#717171]">
                              Hành vi phát hiện
                            </TableHead>
                            <TableHead className="text-xs text-[#717171]">
                              Đối tượng liên quan
                            </TableHead>
                            <TableHead className="text-xs text-[#717171]">
                              Địa chỉ IP nguồn
                            </TableHead>
                            <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
                            <TableHead className="text-xs text-[#717171] text-right">
                              Thao tác
                            </TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {dlpAlerts.length === 0 ? (
                            <TableRow>
                              <TableCell
                                colSpan={6}
                                className="text-center py-8 text-[#717171] text-xs"
                              >
                                <div className="flex flex-col items-center justify-center gap-1.5">
                                  <ShieldCheck className="h-6 w-6 text-[#008A05]" />
                                  <span className="font-medium text-[#222222]">
                                    Cổng Network DLP ICAP Server đang bảo vệ an toàn luồng dữ liệu
                                    Egress
                                  </span>
                                  <span className="text-[11px] text-[#717171]">
                                    Chưa ghi nhận sự cố rò rỉ dữ liệu mật hoặc khóa bí mật ra ngoài
                                    thiết bị biên.
                                  </span>
                                </div>
                              </TableCell>
                            </TableRow>
                          ) : (
                            dlpAlerts.map((alert) => (
                              <TableRow
                                key={alert.id}
                                className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                              >
                                <TableCell>
                                  <Badge
                                    variant={
                                      alert.severity === 'CRITICAL'
                                        ? 'destructive'
                                        : alert.severity === 'HIGH'
                                          ? 'warning'
                                          : 'info'
                                    }
                                  >
                                    {alert.severity}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  <div className="font-semibold text-xs text-[#222222]">
                                    {alert.title}
                                  </div>
                                  <div className="text-[11px] font-mono text-[#717171]">
                                    {alert.ruleCode}
                                  </div>
                                </TableCell>
                                <TableCell className="text-xs text-[#222222]">
                                  {alert.detectedUserName || 'Chưa định danh'}
                                </TableCell>
                                <TableCell className="font-mono text-xs text-[#717171]">
                                  {alert.ipAddress}
                                </TableCell>
                                <TableCell className="text-xs text-[#717171]">
                                  {new Date(alert.detectedAt).toLocaleString('vi-VN')}
                                </TableCell>
                                <TableCell className="text-right">
                                  <InteractiveHoverButton
                                    size="sm"
                                    variant="secondary"
                                    text="Chi tiết"
                                    icon={<Search size={14} />}
                                    onClick={() => {
                                      setSelectedAlert(alert);
                                      setNewStatus(
                                        alert.status === 'OPEN' ? 'INVESTIGATING' : alert.status,
                                      );
                                      setResolutionNote('');
                                      setInvestigationNote('');
                                      setAlertDetailOpen(true);
                                    }}
                                  />
                                </TableCell>
                              </TableRow>
                            ))
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </div>

                  {/* Gateway Integration Blueprint */}
                  <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2 text-xs">
                    <div className="font-bold text-[#222222] flex items-center gap-1.5">
                      <Cpu className="h-4 w-4 text-[#008489]" />
                      <span>
                        Cấu hình tích hợp Gateway DLP chuyên dụng (Edge Proxy / Firewall / NextGen
                        DLP)
                      </span>
                    </div>
                    <p className="text-[#717171] leading-relaxed">
                      Để kết nối Squid Proxy hoặc các cổng biên mạng (Symantec, Forcepoint,
                      BlueCoat, F5) với máy chủ ICAP của hệ thống, thêm định tuyến ICAP service vào
                      cấu hình proxy:
                    </p>
                    <div className="p-3 bg-[#222222] text-[#f7f7f7] rounded-[12px] font-mono text-[11px] overflow-x-auto space-y-1">
                      <div># squid.conf - Network DLP ICAP Service Integration</div>
                      <div className="text-[#008489]">icap_enable on</div>
                      <div>
                        icap_service sda_dlp respmod_precache icap://127.0.0.1:1344/dlp-respmod
                        bypass=0
                      </div>
                      <div>adaptation_access sda_dlp allow all</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          {/* ALERT DETAIL MODAL */}
          <Dialog open={alertDetailOpen} onOpenChange={setAlertDetailOpen}>
            <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Chi tiết cảnh báo an ninh #{selectedAlert?.id}
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Cập nhật trạng thái điều tra theo máy trạng thái nghiêm ngặt
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3.5 py-2 text-xs">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Quy tắc:</span>
                    <span className="font-bold text-[#222222]">{selectedAlert?.ruleCode}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Đối tượng:</span>
                    <span className="font-medium text-[#222222]">
                      {selectedAlert?.detectedUserName}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Địa chỉ IP:</span>
                    <span className="font-bold text-[#222222]">{selectedAlert?.ipAddress}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="alert-status-select" className="font-medium text-[#222222]">
                    Chuyển đổi trạng thái:
                  </label>
                  <select
                    id="alert-status-select"
                    value={newStatus}
                    onChange={(e) =>
                      setNewStatus(
                        e.target.value as 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE',
                      )
                    }
                    className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                  >
                    <option value="OPEN">OPEN (Đang mở)</option>
                    <option value="INVESTIGATING">INVESTIGATING (Đang điều tra)</option>
                    <option value="RESOLVED">RESOLVED (Đã xử lý)</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE (Báo động giả)</option>
                  </select>
                </div>

                {(newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') && (
                  <div className="space-y-1">
                    <label htmlFor="res-note" className="font-medium text-[#222222]">
                      Ghi chú kết luận (Bắt buộc tối thiểu 5 ký tự){' '}
                      <span className="text-[#C13515]">*</span>
                    </label>
                    <Textarea
                      id="res-note"
                      rows={2}
                      value={resolutionNote}
                      onChange={(e) => setResolutionNote(e.target.value)}
                      placeholder="Nêu rõ kết quả xác minh hoặc nguyên nhân báo động giả..."
                      className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                    />
                  </div>
                )}

                <div className="space-y-1">
                  <label htmlFor="inv-note" className="font-medium text-[#222222]">
                    Thêm ghi chú điều tra nội bộ:
                  </label>
                  <Textarea
                    id="inv-note"
                    rows={2}
                    value={investigationNote}
                    onChange={(e) => setInvestigationNote(e.target.value)}
                    placeholder="Ghi nhận các bước rà soát log, trao đổi với người dùng..."
                    className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                  />
                </div>
              </div>

              <DialogFooter className="pt-2">
                <InteractiveHoverButton
                  type="button"
                  variant="ghost"
                  size="sm"
                  text="Đóng"
                  onClick={() => setAlertDetailOpen(false)}
                />
                <InteractiveHoverButton
                  type="button"
                  variant="primary"
                  size="sm"
                  text="Cập nhật cảnh báo"
                  icon={<Check size={14} />}
                  isLoading={isUpdatingAlert}
                  disabled={isUpdatingAlert}
                  onClick={() => void handleUpdateAlertStatus()}
                />
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* CREATE INCIDENT MODAL */}
          <Dialog open={createIncidentOpen} onOpenChange={setCreateIncidentOpen}>
            <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
              <DialogHeader>
                <DialogTitle className="text-base font-semibold text-[#222222]">
                  Lập hồ sơ sự cố an ninh thông tin mới
                </DialogTitle>
                <DialogDescription className="text-xs text-[#717171]">
                  Ghi nhận sự cố để phục vụ quy trình điều tra, khắc phục và báo cáo lãnh đạo
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleCreateIncident} className="space-y-3.5 py-2 text-xs">
                <div className="space-y-1">
                  <label htmlFor="inc-title" className="font-medium text-[#222222]">
                    Tiêu đề sự cố <span className="text-[#C13515]">*</span>
                  </label>
                  <Input
                    id="inc-title"
                    required
                    value={incTitle}
                    onChange={(e) => setIncTitle(e.target.value)}
                    placeholder="Ví dụ: Nghi vấn rò rỉ tài liệu mật phòng Tài chính"
                    className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                  />
                </div>

                <div className="space-y-1">
                  <label htmlFor="inc-summary" className="font-medium text-[#222222]">
                    Tóm tắt diễn biến & đánh giá tác động <span className="text-[#C13515]">*</span>
                  </label>
                  <Textarea
                    id="inc-summary"
                    required
                    rows={4}
                    value={incSummary}
                    onChange={(e) => setIncSummary(e.target.value)}
                    placeholder="Mô tả sự việc, các bằng chứng sơ bộ và mức độ rủi ro đối với tổ chức..."
                    className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                  />
                  <p className="text-[10px] text-[#717171]">
                    Tối thiểu 10 ký tự ({incSummary.trim().length}/10)
                  </p>
                </div>

                <DialogFooter className="pt-2">
                  <InteractiveHoverButton
                    type="button"
                    variant="ghost"
                    size="sm"
                    text="Hủy"
                    onClick={() => setCreateIncidentOpen(false)}
                  />
                  <InteractiveHoverButton
                    type="submit"
                    variant="primary"
                    size="sm"
                    text="Tạo hồ sơ DRAFT"
                    icon={<FileCheck size={14} />}
                    isLoading={isCreatingInc}
                    disabled={isCreatingInc || incSummary.trim().length < 10}
                  />
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
