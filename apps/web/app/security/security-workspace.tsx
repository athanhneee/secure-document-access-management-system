'use client';

import { useState } from 'react';
import { AlertOctagon, FileText, Laptop, Network, QrCode, Settings } from 'lucide-react';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { filterNetworkDlpAlerts } from './helpers';
import { useSecurityData } from './hooks/use-security-data';
import { AlertDetailModal } from './modals/alert-detail-modal';
import { CreateIncidentModal } from './modals/create-incident-modal';
import { EditDetectionRuleModal } from './modals/edit-detection-rule-modal';
import { IncidentDetailModal } from './modals/incident-detail-modal';
import { TerminateSessionModal } from './modals/terminate-session-modal';
import { SecurityWorkspaceHeader } from './security-workspace-header';
import { ActiveSessionsTab } from './tabs/active-sessions-tab';
import { AlertsTab } from './tabs/alerts-tab';
import { DetectionRulesTab } from './tabs/detection-rules-tab';
import { IncidentsTab } from './tabs/incidents-tab';
import { NetworkDlpTab } from './tabs/network-dlp-tab';
import { WatermarkForensicsTab } from './tabs/watermark-forensics-tab';
import type { DetectionRuleItem, IncidentItem, SecurityAlertItem } from './types';

/**
 * Thuật toán: Trung tâm Giám sát An ninh SOC, Truy vết Thủy vân & Điều phối Phản ứng Sự cố (`SecurityWorkspace`)
 * Mục đích: Xử lý cảnh báo bất thường, truy nguyên rò rỉ qua mã thủy vân, ngắt phiên đọc khẩn cấp có ghi lý do kiểm toán, điều phối vòng đời sự cố và cấu hình luật phát hiện.
 */
export function SecurityWorkspace() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetailOpen, setIncidentDetailOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<DetectionRuleItem | null>(null);
  const [editRuleOpen, setEditRuleOpen] = useState(false);

  const data = useSecurityData();
  const dlpAlerts = filterNetworkDlpAlerts(data.alerts);
  const selectedAlert = data.alerts.find((item) => item.id === selectedAlertId) ?? null;
  const pendingTerminateSession =
    data.documentSessions.find((s) => s.id === data.pendingTerminateSessionId) ?? null;
  const activeSessionCount = data.documentSessions.filter((s) => s.status === 'ACTIVE').length;

  function handleSelectAlert(alert: SecurityAlertItem) {
    data.setErrorMessage(null);
    setSelectedAlertId(alert.id);
    setAlertDetailOpen(true);
  }

  function handleOpenCreateIncident() {
    data.setErrorMessage(null);
    setCreateIncidentOpen(true);
  }

  function handleSelectIncident(incident: IncidentItem) {
    data.setErrorMessage(null);
    setSelectedIncidentId(incident.id);
    setIncidentDetailOpen(true);
  }

  function handleOpenEditRule(rule: DetectionRuleItem) {
    data.setErrorMessage(null);
    setSelectedRule(rule);
    setEditRuleOpen(true);
  }

  function handleOpenTerminateSession(sessionId: string) {
    data.setErrorMessage(null);
    data.setPendingTerminateSessionId(sessionId);
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
            <SecurityWorkspaceHeader
              isLoading={data.isLoading}
              message={data.message}
              errorMessage={data.errorMessage}
              onRefresh={() => void data.refreshData()}
              onOpenCreateIncident={handleOpenCreateIncident}
            />

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
                  onOpenCreateIncident={handleOpenCreateIncident}
                  onSelectIncident={handleSelectIncident}
                />
              </TabsContent>
              <TabsContent value="detection" className="space-y-4">
                <DetectionRulesTab
                  detectionRules={data.detectionRules}
                  onRunDetection={data.runDetection}
                  onEditRule={handleOpenEditRule}
                />
              </TabsContent>
              <TabsContent value="sessions" className="space-y-4">
                <ActiveSessionsTab
                  documentSessions={data.documentSessions}
                  terminatingSessionId={data.terminatingSessionId}
                  onTerminateSession={handleOpenTerminateSession}
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

            <IncidentDetailModal
              open={incidentDetailOpen}
              onOpenChange={(open) => {
                setIncidentDetailOpen(open);
                if (!open) setSelectedIncidentId(null);
              }}
              incidentId={selectedIncidentId}
              onClearError={() => data.setErrorMessage(null)}
              onSuccess={handleModalSuccess}
              onError={data.setErrorMessage}
            />

            <EditDetectionRuleModal
              open={editRuleOpen}
              onOpenChange={(open) => {
                setEditRuleOpen(open);
                if (!open) setSelectedRule(null);
              }}
              rule={selectedRule}
              onClearError={() => data.setErrorMessage(null)}
              onSuccess={handleModalSuccess}
              onError={data.setErrorMessage}
            />

            <TerminateSessionModal
              open={data.pendingTerminateSessionId !== null}
              onOpenChange={(open) => {
                if (!open) data.setPendingTerminateSessionId(null);
              }}
              session={pendingTerminateSession}
              isSubmitting={data.terminatingSessionId !== null}
              onConfirm={(reason) => data.terminateSession(reason)}
              onError={data.setErrorMessage}
            />
          </div>
        </DialogErrorProvider>
      </AppLayout>
    </AuthGuard>
  );
}
