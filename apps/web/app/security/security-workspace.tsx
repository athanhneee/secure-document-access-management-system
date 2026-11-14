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
import { DialogErrorProvider } from '@/components/ui/dialog';
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
 * Mục đích: Xử lý cảnh báo bất thường, truy nguyên rò rỉ qua mã thủy vân, ngắt phiên đọc khẩn cấp và theo dõi Network DLP.
 */
export function SecurityWorkspace() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);

  const data = useSecurityData();
  const dlpAlerts = filterNetworkDlpAlerts(data.alerts);
  const selectedAlert = data.alerts.find((item) => item.id === selectedAlertId) ?? null;
  const activeSessionCount = data.documentSessions.filter((s) => s.status === 'ACTIVE').length;

  function handleSelectAlert(alert: SecurityAlertItem) {
    setSelectedAlertId(alert.id);
    setAlertDetailOpen(true);
  }

  async function handleModalSuccess(msg: string) {
    data.setMessage(msg);
    void data.refreshData({ silent: true });
  }

  return (
    <AuthGuard requiredRole="SECURITY_OFFICER">
      <AppLayout>
        <DialogErrorProvider
          errorMessage={data.errorMessage}
          onDismiss={() => data.setErrorMessage(null)}
        >
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Badge variant="destructive">Security Officer</Badge>
                  <span className="text-xs text-[#717171]">Phân hệ An ninh Thông tin</span>
                </div>
                <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                  Giám sát An ninh &amp; Điều tra Sự cố
                </h1>
                <p className="text-xs text-[#717171]">
                  Xử lý cảnh báo xâm phạm, điều tra provenance watermark, xử lý sự cố và luật phát
                  hiện
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <InteractiveHoverButton
                  variant="secondary"
                  size="sm"
                  text="Làm mới"
                  icon={
                    <RefreshCw
                      size={16}
                      strokeWidth={1.75}
                      className={data.isLoading ? 'animate-spin' : ''}
                      aria-hidden="true"
                    />
                  }
                  onClick={() => void data.refreshData()}
                  disabled={data.isLoading}
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

            {data.message && (
              <Alert variant="success" className="text-xs">
                <CheckCircle2
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#008A05]"
                  aria-hidden="true"
                />
                <AlertDescription className="ml-2">{data.message}</AlertDescription>
              </Alert>
            )}

            {data.errorMessage && (
              <Alert variant="destructive" className="text-xs">
                <AlertTriangle
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#C13515]"
                  aria-hidden="true"
                />
                <div className="ml-2 flex flex-wrap items-center justify-between gap-2">
                  <AlertDescription>{data.errorMessage}</AlertDescription>
                  <InteractiveHoverButton
                    type="button"
                    variant="secondary"
                    size="sm"
                    text="Thử lại"
                    icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={() => void data.refreshData()}
                    disabled={data.isLoading}
                  />
                </div>
              </Alert>
            )}

            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
              <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-6 h-auto min-h-11 rounded-[20px] p-1.5 md:h-11 md:rounded-full md:p-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
                <TabsTrigger value="alerts" className="flex items-center gap-1.5 text-xs">
                  <AlertOctagon size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Cảnh báo ({data.alerts.length})</span>
                </TabsTrigger>
                <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                  <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Truy vết Watermark</span>
                </TabsTrigger>
                <TabsTrigger value="incidents" className="flex items-center gap-1.5 text-xs">
                  <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Báo cáo sự cố ({data.incidents.length})</span>
                </TabsTrigger>
                <TabsTrigger value="sessions" className="flex items-center gap-1.5 text-xs">
                  <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Phiên đọc ({activeSessionCount})</span>
                </TabsTrigger>
                <TabsTrigger value="detection" className="flex items-center gap-1.5 text-xs">
                  <Settings size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Luật phát hiện ({data.detectionRules.length})</span>
                </TabsTrigger>
                <TabsTrigger value="network-dlp" className="flex items-center gap-1.5 text-xs">
                  <Network size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Network DLP ({dlpAlerts.length})</span>
                </TabsTrigger>
              </TabsList>

              <TabsContent value="alerts" className="space-y-4">
                <AlertsTab alerts={data.alerts} onSelectAlert={handleSelectAlert} />
              </TabsContent>
              <TabsContent value="watermark-trace" className="space-y-4">
                <WatermarkForensicsTab
                  onClearError={() => data.setErrorMessage(null)}
                  onMessage={data.setMessage}
                  onError={data.setErrorMessage}
                />
              </TabsContent>
              <TabsContent value="incidents" className="space-y-4">
                <IncidentsTab
                  incidents={data.incidents}
                  onOpenCreateIncident={() => setCreateIncidentOpen(true)}
                />
              </TabsContent>
              <TabsContent value="detection" className="space-y-4">
                <DetectionRulesTab
                  detectionRules={data.detectionRules}
                  onRunDetection={data.runDetection}
                />
              </TabsContent>
              <TabsContent value="sessions" className="space-y-4">
                <ActiveSessionsTab
                  documentSessions={data.documentSessions}
                  terminatingSessionId={data.terminatingSessionId}
                  onTerminateSession={(id) => data.setPendingTerminateSessionId(id)}
                />
              </TabsContent>
              <TabsContent value="network-dlp" className="space-y-4">
                <NetworkDlpTab
                  dlpAlerts={dlpAlerts}
                  gatewayHealth={data.gatewayHealth}
                  onSelectAlert={handleSelectAlert}
                />
              </TabsContent>
            </Tabs>

            <AlertDetailModal
              open={alertDetailOpen}
              onOpenChange={(open) => {
                setAlertDetailOpen(open);
                if (!open) setSelectedAlertId(null);
              }}
              alert={selectedAlert}
              onClearError={() => data.setErrorMessage(null)}
              onOptimisticUpdate={data.applyOptimisticAlertUpdate}
              onSuccess={handleModalSuccess}
              onError={data.setErrorMessage}
            />

            <CreateIncidentModal
              open={createIncidentOpen}
              onOpenChange={setCreateIncidentOpen}
              onClearError={() => data.setErrorMessage(null)}
              onSuccess={handleModalSuccess}
              onError={data.setErrorMessage}
            />

            <ConfirmDialog
              open={data.pendingTerminateSessionId !== null}
              onOpenChange={(open) => {
                if (!open) data.setPendingTerminateSessionId(null);
              }}
              title="Cưỡng bức ngắt phiên truy cập tài liệu"
              description="Bạn có chắc chắn muốn ngắt kết nối phiên truy cập tài liệu này ngay lập tức không?"
              confirmText="Ngắt phiên ngay"
              variant="danger"
              isLoading={data.terminatingSessionId !== null}
              onConfirm={() => void data.terminateSession()}
            />
          </div>
        </DialogErrorProvider>
      </AppLayout>
    </AuthGuard>
  );
}
