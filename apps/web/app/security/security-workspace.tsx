'use client';

import { useState } from 'react';
import {
  AlertOctagon,
  Anchor,
  FileText,
  Laptop,
  Network,
  QrCode,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useSecurityData } from './hooks/use-security-data';
import { AlertDetailModal } from './modals/alert-detail-modal';
import { CreateIncidentModal } from './modals/create-incident-modal';
import { EditDetectionRuleModal } from './modals/edit-detection-rule-modal';
import { IncidentDetailModal } from './modals/incident-detail-modal';
import { TerminateSessionModal } from './modals/terminate-session-modal';
import { SecurityWorkspaceHeader } from './security-workspace-header';
import { ActiveSessionsTab } from './tabs/active-sessions-tab';
import { AlertsTab } from './tabs/alerts-tab';
import { AuditIntegrityTab } from './tabs/audit-integrity-tab';
import { DetectionRulesTab } from './tabs/detection-rules-tab';
import { IncidentsTab } from './tabs/incidents-tab';
import { NetworkDlpTab } from './tabs/network-dlp-tab';
import { PolicySimulatorTab } from './tabs/policy-simulator-tab';
import { WatermarkForensicsTab } from './tabs/watermark-forensics-tab';
import type {
  DetectionRuleItem,
  IncidentDraftPrefill,
  IncidentItem,
  SecurityAlertItem,
} from './types';

/**
 * Thuật toán: Trung Tâm Giám Sát SOC Cô Lập Sau `AuthGuard` & Lọc Thao Tác Theo Quyền Thực (`SecurityWorkspace`)
 * Mục đích:
 *   - Chỉ thực thi `useSecurityData()` sau khi `AuthGuard` xác nhận `requiredPortal="SECURITY_OFFICER"`.
 *   - Cung cấp đầy đủ 8 phân hệ theo đúng ma trận quyền `SECURITY_OFFICER` (bao gồm UC32 Neo Audit, AUDIT_LOG và UC09 Mô phỏng ABAC) mà vẫn bảo toàn tuyệt đối Phân tách nhiệm vụ SoD (#04, #05, #16, #28).
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
  const { user, hasPermission } = useAuth();
  const canViewAlerts = hasPermission('SECURITY_ALERT:VIEW');
  const canManageAlerts = hasPermission('SECURITY_ALERT:MANAGE');
  const canTraceWatermark = hasPermission('WATERMARK_INSTANCE:TRACE');
  const canCreateIncident = hasPermission('INCIDENT_REPORT:CREATE');
  const canManageIncidents = hasPermission('INCIDENT_REPORT:MANAGE');
  const canViewIncidents = canViewAlerts || canCreateIncident || canManageIncidents;
  const canTerminateSession = hasPermission('ACCESS_SESSION:TERMINATE');
  const canViewAudit = hasPermission('AUDIT_LOG:VIEW');
  const canCreateAnchor = Boolean(user?.roles?.includes('SECURITY_OFFICER')) && canViewAudit;
  const canSimulatePolicy = hasPermission('POLICY:SIMULATE');

  const permittedTabs = [
    canViewAlerts ? 'alerts' : null,
    canTraceWatermark ? 'watermark-trace' : null,
    canViewIncidents ? 'incidents' : null,
    canTerminateSession ? 'sessions' : null,
    canViewAlerts || canManageAlerts ? 'detection' : null,
    canViewAlerts ? 'network-dlp' : null,
    canViewAudit ? 'audit-integrity' : null,
    canSimulatePolicy ? 'policy-simulator' : null,
  ].filter((t): t is string => t !== null);

  const [selectedTab, setSelectedTab] = useState('alerts');
  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'alerts');

  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);
  const [incidentPrefill, setIncidentPrefill] = useState<IncidentDraftPrefill | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetailOpen, setIncidentDetailOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<DetectionRuleItem | null>(null);
  const [editRuleOpen, setEditRuleOpen] = useState(false);

  const data = useSecurityData();
  const selectedAlert =
    data.alerts.find((item) => item.id === selectedAlertId) ??
    data.dlpAlerts.find((item) => item.id === selectedAlertId) ??
    null;
  const pendingTerminateSession =
    data.documentSessions.find((s) => s.id === data.pendingTerminateSessionId) ?? null;

  function handleSelectAlert(alert: SecurityAlertItem) {
    data.setErrorMessage(null);
    setSelectedAlertId(alert.id);
    setAlertDetailOpen(true);
  }

  function handleOpenCreateIncident(prefill?: IncidentDraftPrefill) {
    data.setErrorMessage(null);
    setIncidentPrefill(prefill ?? null);
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
          onRefresh={() => {
            data.setMessage(null);
            void data.refreshData();
          }}
          onOpenCreateIncident={() => handleOpenCreateIncident()}
        />

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-4">
            <TabsList className="flex flex-wrap w-full h-auto min-h-10 rounded-[18px] p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewAlerts && (
                <TabsTrigger value="alerts" className="flex items-center gap-1.5 text-xs">
                  <AlertOctagon size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Cảnh báo ({data.alertsTotal})</span>
                </TabsTrigger>
              )}
              {canTraceWatermark && (
                <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                  <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Truy vết watermark</span>
                </TabsTrigger>
              )}
              {canViewIncidents && (
                <TabsTrigger value="incidents" className="flex items-center gap-1.5 text-xs">
                  <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Hồ sơ sự cố ({data.incidentsTotal})</span>
                </TabsTrigger>
              )}
              {canTerminateSession && (
                <TabsTrigger value="sessions" className="flex items-center gap-1.5 text-xs">
                  <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Phiên đọc ({data.activeSessionsCount})</span>
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
                  <span>Giám sát DLP mạng ({data.dlpAlertsTotal})</span>
                </TabsTrigger>
              )}
              {canViewAudit && (
                <TabsTrigger value="audit-integrity" className="flex items-center gap-1.5 text-xs">
                  <Anchor size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Toàn vẹn &amp; Neo Audit</span>
                </TabsTrigger>
              )}
              {canSimulatePolicy && (
                <TabsTrigger value="policy-simulator" className="flex items-center gap-1.5 text-xs">
                  <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Mô phỏng ABAC</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canViewAlerts && (
              <TabsContent value="alerts" className="space-y-4">
                <AlertsTab
                  alerts={data.alerts}
                  total={data.alertsTotal}
                  page={data.alertsPage}
                  severityFilter={data.alertsSeverity}
                  statusFilter={data.alertsStatus}
                  searchQuery={data.alertsSearch}
                  tabError={data.tabErrors.alerts}
                  onSeverityChange={data.setAlertsSeverity}
                  onStatusChange={data.setAlertsStatus}
                  onSearchChange={data.setAlertsSearch}
                  onPageChange={data.setAlertsPage}
                  onSelectAlert={handleSelectAlert}
                />
              </TabsContent>
            )}
            {canTraceWatermark && (
              <TabsContent value="watermark-trace" className="space-y-4">
                <WatermarkForensicsTab
                  canCreateIncident={canCreateIncident}
                  onCreateIncidentFromWatermark={(prefill) => handleOpenCreateIncident(prefill)}
                  onClearError={() => data.setErrorMessage(null)}
                  onMessage={data.setMessage}
                  onError={data.setErrorMessage}
                />
              </TabsContent>
            )}
            {canViewIncidents && (
              <TabsContent value="incidents" className="space-y-4">
                <IncidentsTab
                  incidents={data.incidents}
                  total={data.incidentsTotal}
                  page={data.incidentsPage}
                  statusFilter={data.incidentsStatus}
                  searchQuery={data.incidentsSearch}
                  tabError={data.tabErrors.incidents}
                  canCreateIncident={canCreateIncident}
                  onStatusChange={data.setIncidentsStatus}
                  onSearchChange={data.setIncidentsSearch}
                  onPageChange={data.setIncidentsPage}
                  onOpenCreateIncident={() => handleOpenCreateIncident()}
                  onSelectIncident={handleSelectIncident}
                />
              </TabsContent>
            )}
            {(canViewAlerts || canManageAlerts) && (
              <TabsContent value="detection" className="space-y-4">
                <DetectionRulesTab
                  detectionRules={data.detectionRules}
                  isRunningDetection={data.isRunningDetection}
                  tabError={data.tabErrors.rules}
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
                  totalCount={data.sessionsTotal}
                  activeCount={data.activeSessionsCount}
                  page={data.sessionsPage}
                  statusFilter={data.sessionsStatus}
                  searchQuery={data.sessionsSearch}
                  tabError={data.tabErrors.sessions}
                  terminatingSessionId={data.terminatingSessionId}
                  canTerminateSession={canTerminateSession}
                  onStatusChange={data.setSessionsStatus}
                  onSearchChange={data.setSessionsSearch}
                  onPageChange={data.setSessionsPage}
                  onTerminateSession={handleOpenTerminateSession}
                />
              </TabsContent>
            )}
            {canViewAlerts && (
              <TabsContent value="network-dlp" className="space-y-4">
                <NetworkDlpTab
                  dlpAlerts={data.dlpAlerts}
                  totalDlpAlerts={data.dlpAlertsTotal}
                  dlpStatus={data.dlpStatus}
                  tabError={data.tabErrors.dlp}
                  onSelectAlert={handleSelectAlert}
                />
              </TabsContent>
            )}
            {canViewAudit && (
              <TabsContent value="audit-integrity" className="space-y-4">
                <AuditIntegrityTab
                  canCreateAnchor={canCreateAnchor}
                  onMessage={data.setMessage}
                  onError={data.setErrorMessage}
                />
              </TabsContent>
            )}
            {canSimulatePolicy && (
              <TabsContent value="policy-simulator" className="space-y-4">
                <PolicySimulatorTab />
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
          canManageAlerts={canManageAlerts}
          canCreateIncident={canCreateIncident}
          onCreateIncidentFromAlert={(prefill) => handleOpenCreateIncident(prefill)}
          onClearError={() => data.setErrorMessage(null)}
          onOptimisticUpdate={data.applyOptimisticAlertUpdate}
          onSuccess={handleModalSuccess}
          onError={data.setErrorMessage}
        />

        <CreateIncidentModal
          open={createIncidentOpen}
          onOpenChange={(open) => {
            setCreateIncidentOpen(open);
            if (!open) setIncidentPrefill(null);
          }}
          alerts={data.alerts}
          prefill={incidentPrefill}
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
          canManageIncidents={canManageIncidents}
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
