'use client';

import { useState } from 'react';
import { AlertOctagon, FileText, Laptop, Network, QrCode, Settings } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
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
 * Thuật toán: Trung Tâm Giám Sát SOC Cô Lập Sau `AuthGuard` & Lọc Thao Tác Theo Quyền (`SecurityWorkspace`)
 * Mục đích:
 *   - Chỉ thực thi `useSecurityData()` sau khi `AuthGuard` xác nhận vai trò `SECURITY_OFFICER`.
 *   - Ẩn các tab và nút thao tác không thuộc tập quyền hiệu lực (`SECURITY_ALERT:VIEW`/`MANAGE`, `WATERMARK_INSTANCE:TRACE`, `INCIDENT_REPORT:CREATE`/`MANAGE`, `ACCESS_SESSION:TERMINATE`).
 */
export function SecurityWorkspace() {
  return (
    <AuthGuard requiredPortal="SECURITY_OFFICER">
      <AppLayout>
        <SecurityWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function SecurityWorkspaceContent() {
  const { hasPermission } = useAuth();
  const canViewAlerts = hasPermission('SECURITY_ALERT:VIEW');
  const canManageAlerts = hasPermission('SECURITY_ALERT:MANAGE');
  const canTraceWatermark = hasPermission('WATERMARK_INSTANCE:TRACE');
  const canCreateIncident = hasPermission('INCIDENT_REPORT:CREATE');
  const canManageIncidents = hasPermission('INCIDENT_REPORT:MANAGE') || canCreateIncident;
  const canTerminateSession = hasPermission('ACCESS_SESSION:TERMINATE');

  const permittedTabs = [
    canViewAlerts ? 'alerts' : null,
    canTraceWatermark ? 'watermark-trace' : null,
    canManageIncidents ? 'incidents' : null,
    canTerminateSession ? 'sessions' : null,
    canViewAlerts || canManageAlerts ? 'detection' : null,
    canViewAlerts ? 'network-dlp' : null,
  ].filter((t): t is string => t !== null);

  const [selectedTab, setSelectedTab] = useState('alerts');
  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'alerts');

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
    <DialogErrorProvider
      errorMessage={data.errorMessage}
      onDismiss={() => data.setErrorMessage(null)}
    >
      <div className="space-y-4">
        <SecurityWorkspaceHeader
          isLoading={data.isLoading}
          message={data.message}
          errorMessage={data.errorMessage}
          canCreateIncident={canCreateIncident}
          onRefresh={() => void data.refreshData()}
          onOpenCreateIncident={handleOpenCreateIncident}
        />

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 xl:inline-flex xl:w-auto h-auto min-h-10 rounded-[18px] xl:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewAlerts && (
                <TabsTrigger value="alerts" className="flex items-center gap-1.5 text-xs">
                  <AlertOctagon size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Cảnh báo ({data.alerts.length})</span>
                </TabsTrigger>
              )}
              {canTraceWatermark && (
                <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                  <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Truy vết watermark</span>
                </TabsTrigger>
              )}
              {canManageIncidents && (
                <TabsTrigger value="incidents" className="flex items-center gap-1.5 text-xs">
                  <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Hồ sơ sự cố ({data.incidents.length})</span>
                </TabsTrigger>
              )}
              {canTerminateSession && (
                <TabsTrigger value="sessions" className="flex items-center gap-1.5 text-xs">
                  <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Phiên đọc ({activeSessionCount})</span>
                </TabsTrigger>
              )}
              {(canViewAlerts || canManageAlerts) && (
                <TabsTrigger value="detection" className="flex items-center gap-1.5 text-xs">
                  <Settings size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Quy tắc phát hiện ({data.detectionRules.length})</span>
                </TabsTrigger>
              )}
              {canViewAlerts && (
                <TabsTrigger value="network-dlp" className="flex items-center gap-1.5 text-xs">
                  <Network size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Giám sát DLP mạng ({dlpAlerts.length})</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canViewAlerts && (
              <TabsContent value="alerts" className="space-y-4">
                <AlertsTab alerts={data.alerts} onSelectAlert={handleSelectAlert} />
              </TabsContent>
            )}
            {canTraceWatermark && (
              <TabsContent value="watermark-trace" className="space-y-4">
                <WatermarkForensicsTab
                  onClearError={() => data.setErrorMessage(null)}
                  onMessage={data.setMessage}
                  onError={data.setErrorMessage}
                />
              </TabsContent>
            )}
            {canManageIncidents && (
              <TabsContent value="incidents" className="space-y-4">
                <IncidentsTab
                  incidents={data.incidents}
                  canCreateIncident={canCreateIncident}
                  onOpenCreateIncident={handleOpenCreateIncident}
                  onSelectIncident={handleSelectIncident}
                />
              </TabsContent>
            )}
            {(canViewAlerts || canManageAlerts) && (
              <TabsContent value="detection" className="space-y-4">
                <DetectionRulesTab
                  detectionRules={data.detectionRules}
                  canManageRules={canManageAlerts}
                  onRunDetection={data.runDetection}
                  onEditRule={handleOpenEditRule}
                />
              </TabsContent>
            )}
            {canTerminateSession && (
              <TabsContent value="sessions" className="space-y-4">
                <ActiveSessionsTab
                  documentSessions={data.documentSessions}
                  terminatingSessionId={data.terminatingSessionId}
                  canTerminateSession={canTerminateSession}
                  onTerminateSession={handleOpenTerminateSession}
                />
              </TabsContent>
            )}
            {canViewAlerts && (
              <TabsContent value="network-dlp" className="space-y-4">
                <NetworkDlpTab
                  dlpAlerts={dlpAlerts}
                  gatewayHealth={data.gatewayHealth}
                  onSelectAlert={handleSelectAlert}
                />
              </TabsContent>
            )}
          </Tabs>
        )}

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
  );
}
