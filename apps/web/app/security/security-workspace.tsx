'use client';

import { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  FileCheck,
  FileText,
  Laptop,
  Network,
  QrCode,
  RefreshCw,
  Settings,
} from 'lucide-react';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { filterNetworkDlpAlerts } from './helpers';
import { useSecurityData } from './hooks/use-security-data';
import { AlertDetailModal } from './modals/alert-detail-modal';
import { CreateIncidentModal } from './modals/create-incident-modal';
import { ActiveSessionsTab } from './tabs/active-sessions-tab';
import { AlertsTab } from './tabs/alerts-tab';
import { DetectionRulesTab } from './tabs/detection-rules-tab';
import { IncidentsTab } from './tabs/incidents-tab';
import { NetworkDlpTab } from './tabs/network-dlp-tab';
import { WatermarkForensicsTab } from './tabs/watermark-forensics-tab';
import type { SecurityAlertItem } from './types';

/**
 * Thuật toán: Trung tâm Giám sát An ninh SOC, Truy vết Thủy vân & Điều phối Phản ứng Sự cố (`SecurityWorkspace`)
 * Mục đích: Cung cấp bảng điều khiển tập trung cho cán bộ an ninh xử lý cảnh báo bất thường, truy nguyên rò rỉ tài liệu qua mã thủy vân, ngắt phiên đọc khẩn cấp và theo dõi vi phạm Network DLP.
 * Cơ chế hoạt động:
 *   - Phân tách luồng cảnh báo cổng ICAP DLP (`filterNetworkDlpAlerts`) và điều phối dữ liệu thời gian thực qua `useSecurityData` dưới lớp bảo vệ `AuthGuard` (`SECURITY_OFFICER`).
 */
export function SecurityWorkspace() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlertItem | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);

  const {
    alerts,
    incidents,
    detectionRules,
    documentSessions,
    terminatingSessionId,
    pendingTerminateSessionId,
    setPendingTerminateSessionId,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    refreshData,
    runDetection,
    terminateSession,
  } = useSecurityData();

  const dlpAlerts = filterNetworkDlpAlerts(alerts);

  function handleSelectAlert(alert: SecurityAlertItem) {
    setSelectedAlert(alert);
    setAlertDetailOpen(true);
  }

  async function handleModalSuccess(msg: string) {
    setMessage(msg);
    await refreshData();
  }

  return (
    <AuthGuard requiredRole="SECURITY_OFFICER">
      <AppLayout>
        <div className="space-y-6">
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
                icon={
                  <RefreshCw
                    size={16}
                    strokeWidth={1.75}
                    className={isLoading ? 'animate-spin' : ''}
                    aria-hidden="true"
                  />
                }
                onClick={() => void refreshData()}
                disabled={isLoading}
              />
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Lập báo cáo sự cố"
                icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => setCreateIncidentOpen(true)}
              />
            </div>
          </div>

          {message && (
            <Alert variant="success" className="text-xs">
              <CheckCircle2
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#008A05]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{message}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert variant="destructive" className="text-xs">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#C13515]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-6 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger value="alerts" className="flex items-center gap-1.5 text-xs">
                <AlertOctagon size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Cảnh báo ({alerts.length})</span>
              </TabsTrigger>
              <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Truy vết Watermark</span>
              </TabsTrigger>
              <TabsTrigger value="incidents" className="flex items-center gap-1.5 text-xs">
                <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Báo cáo sự cố ({incidents.length})</span>
              </TabsTrigger>
              <TabsTrigger value="sessions" className="flex items-center gap-1.5 text-xs">
                <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>
                  Phiên đọc ({documentSessions.filter((s) => s.status === 'ACTIVE').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="detection" className="flex items-center gap-1.5 text-xs">
                <Settings size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Luật phát hiện ({detectionRules.length})</span>
              </TabsTrigger>
              <TabsTrigger value="network-dlp" className="flex items-center gap-1.5 text-xs">
                <Network size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Network DLP ({dlpAlerts.length})</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="alerts" className="space-y-4">
              <AlertsTab alerts={alerts} onSelectAlert={handleSelectAlert} />
            </TabsContent>

            <TabsContent value="watermark-trace" className="space-y-4">
              <WatermarkForensicsTab
                onClearError={() => setErrorMessage(null)}
                onMessage={setMessage}
                onError={setErrorMessage}
              />
            </TabsContent>

            <TabsContent value="incidents" className="space-y-4">
              <IncidentsTab
                incidents={incidents}
                onOpenCreateIncident={() => setCreateIncidentOpen(true)}
              />
            </TabsContent>

            <TabsContent value="detection" className="space-y-4">
              <DetectionRulesTab
                detectionRules={detectionRules}
                onRunDetection={() => void runDetection()}
              />
            </TabsContent>

            <TabsContent value="sessions" className="space-y-4">
              <ActiveSessionsTab
                documentSessions={documentSessions}
                terminatingSessionId={terminatingSessionId}
                onTerminateSession={(id) => setPendingTerminateSessionId(id)}
              />
            </TabsContent>

            <TabsContent value="network-dlp" className="space-y-4">
              <NetworkDlpTab dlpAlerts={dlpAlerts} onSelectAlert={handleSelectAlert} />
            </TabsContent>
          </Tabs>

          <AlertDetailModal
            open={alertDetailOpen}
            onOpenChange={(open) => {
              setAlertDetailOpen(open);
              if (!open) setSelectedAlert(null);
            }}
            alert={selectedAlert}
            onClearError={() => setErrorMessage(null)}
            onSuccess={handleModalSuccess}
            onError={setErrorMessage}
          />

          <CreateIncidentModal
            open={createIncidentOpen}
            onOpenChange={setCreateIncidentOpen}
            onClearError={() => setErrorMessage(null)}
            onSuccess={handleModalSuccess}
            onError={setErrorMessage}
          />

          <ConfirmDialog
            open={pendingTerminateSessionId !== null}
            onOpenChange={(open) => {
              if (!open) setPendingTerminateSessionId(null);
            }}
            title="Cưỡng bức ngắt phiên truy cập tài liệu"
            description="Bạn có chắc chắn muốn ngắt kết nối phiên truy cập tài liệu này ngay lập tức không?"
            confirmText="Ngắt phiên ngay"
            variant="danger"
            isLoading={terminatingSessionId !== null}
            onConfirm={() => void terminateSession()}
          />
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
