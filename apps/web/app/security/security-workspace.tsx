'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
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
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { useWorkspaceTabSync } from '@/lib/use-workspace-tab-sync';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { WORKSPACE_TAB_EVENT } from '@/components/navigation/notification-bell-dialog';
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
  DocumentSessionItem,
  IncidentDraftPrefill,
  IncidentItem,
  SecurityAlertItem,
} from './types';

/**
 * Thuật toán: Trung Tâm Giám Sát SOC Cô Lập Sau `AuthGuard`, Đồng Bộ `?tab=` Có Lọc RBAC & Cô Lập Lỗi Hộp Thoại (`SecurityWorkspace`)
 * Mục đích:
 *   - Chỉ thực thi `useSecurityData()` sau khi `AuthGuard` xác nhận `requiredPortal="SECURITY_OFFICER"`.
 *   - Đồng bộ hai chiều `?tab=` qua `useWorkspaceTabSync(permittedTabs, 'alerts')` và tách riêng `dialogError` của modal khỏi `errorMessage` của trang chính.
 */
export function SecurityWorkspace() {
  return (
    <AuthGuard requiredPortal="SECURITY_OFFICER">
      <AppLayout>
        <Suspense fallback={null}>
          <SecurityWorkspaceContent />
        </Suspense>
      </AppLayout>
    </AuthGuard>
  );
}

function SecurityWorkspaceContent() {
  const { user, hasPermission, hasGlobalPermission } = useAuth();
  const isReadOnlyAuditor = Boolean(user?.roles?.includes('AUDITOR'));
  const canViewAlerts = hasPermission('SECURITY_ALERT:VIEW');
  const canManageAlerts = hasPermission('SECURITY_ALERT:MANAGE');
  const canManageRules = hasGlobalPermission('SECURITY_ALERT:MANAGE');
  const canTraceWatermark = hasPermission('WATERMARK_INSTANCE:TRACE');
  const canCreateIncident = !isReadOnlyAuditor && hasPermission('INCIDENT_REPORT:CREATE');
  const canManageIncidents = !isReadOnlyAuditor && hasPermission('INCIDENT_REPORT:MANAGE');
  const canViewIncidents =
    canViewAlerts ||
    hasPermission('INCIDENT_REPORT:CREATE') ||
    hasPermission('INCIDENT_REPORT:MANAGE');
  const canTerminateSession = hasPermission('ACCESS_SESSION:TERMINATE');
  const canViewAudit = hasPermission('AUDIT_LOG:VIEW');
  const canCreateAnchor = Boolean(user?.roles?.includes('SECURITY_OFFICER')) && canViewAudit;
  const canSimulatePolicy = hasGlobalPermission('POLICY:SIMULATE');

  const permittedTabs = useMemo(
    () =>
      [
        canViewAlerts ? 'alerts' : null,
        canTraceWatermark ? 'watermark-trace' : null,
        canViewIncidents ? 'incidents' : null,
        canTerminateSession ? 'sessions' : null,
        canViewAlerts || canManageAlerts ? 'detection' : null,
        canViewAlerts ? 'network-dlp' : null,
        canViewAudit ? 'audit-integrity' : null,
        canSimulatePolicy ? 'policy-simulator' : null,
      ].filter((t): t is string => t !== null),
    [
      canViewAlerts,
      canTraceWatermark,
      canViewIncidents,
      canTerminateSession,
      canManageAlerts,
      canViewAudit,
      canSimulatePolicy,
    ],
  );

  const [activeTab, setActiveTab] = useWorkspaceTabSync(permittedTabs, 'alerts');
  const [refreshSignal, setRefreshSignal] = useState(0);

  useEffect(() => {
    function handleTabSync(event: Event) {
      const detail = (event as CustomEvent<{ path?: string; tab?: string }>).detail;
      if (detail?.path === '/security' && detail.tab && permittedTabs.includes(detail.tab)) {
        setActiveTab(detail.tab);
      }
    }
    window.addEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
    return () => window.removeEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
  }, [permittedTabs, setActiveTab]);

  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedAlertSnapshot, setSelectedAlertSnapshot] = useState<SecurityAlertItem | null>(
    null,
  );
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [createIncidentOpen, setCreateIncidentOpen] = useState(false);
  const [incidentPrefill, setIncidentPrefill] = useState<IncidentDraftPrefill | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetailOpen, setIncidentDetailOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<DetectionRuleItem | null>(null);
  const [editRuleOpen, setEditRuleOpen] = useState(false);
  const [pendingTerminateSessionSnapshot, setPendingTerminateSessionSnapshot] =
    useState<DocumentSessionItem | null>(null);

  const data = useSecurityData();

  useEffect(() => {
    const activePendingId = data.pendingTerminateSessionId;
    if (!activePendingId) return;
    return subscribeRealtimeEvent<{
      id?: string;
      sessionId?: string;
      status?: string;
      reason?: string;
    }>('ACCESS_SESSION_UPDATED', (event) => {
      const evId = event.payload?.sessionId ?? event.payload?.id;
      const nextStatus = event.payload?.status;
      if (evId === activePendingId && typeof nextStatus === 'string') {
        setPendingTerminateSessionSnapshot((prev) =>
          prev && prev.id === activePendingId
            ? {
                ...prev,
                status: nextStatus,
                ...(typeof event.payload?.reason === 'string'
                  ? { terminatedReason: event.payload.reason }
                  : {}),
              }
            : prev,
        );
      }
    });
  }, [data.pendingTerminateSessionId]);

  const liveSelectedAlert =
    data.alerts.find((item) => item.id === selectedAlertId) ??
    data.dlpAlerts.find((item) => item.id === selectedAlertId) ??
    null;
  const selectedAlert =
    liveSelectedAlert ??
    (selectedAlertSnapshot && selectedAlertSnapshot.id === selectedAlertId
      ? selectedAlertSnapshot
      : null);

  const livePendingTerminateSession =
    data.documentSessions.find((s) => s.id === data.pendingTerminateSessionId) ?? null;
  const matchedTerminateSnapshot =
    pendingTerminateSessionSnapshot &&
    pendingTerminateSessionSnapshot.id === data.pendingTerminateSessionId
      ? pendingTerminateSessionSnapshot
      : null;
  const pendingTerminateSession =
    matchedTerminateSnapshot && matchedTerminateSnapshot.status !== 'ACTIVE'
      ? {
          ...(livePendingTerminateSession ?? matchedTerminateSnapshot),
          ...matchedTerminateSnapshot,
        }
      : (livePendingTerminateSession ?? matchedTerminateSnapshot);

  function handleSelectAlert(alert: SecurityAlertItem) {
    data.setDialogError(null);
    setSelectedAlertId(alert.id);
    setSelectedAlertSnapshot(alert);
    setAlertDetailOpen(true);
  }

  function handleOpenCreateIncident(prefill?: IncidentDraftPrefill) {
    data.setDialogError(null);
    setIncidentPrefill(prefill ?? null);
    setCreateIncidentOpen(true);
  }

  function handleSelectIncident(incident: IncidentItem) {
    data.setDialogError(null);
    setSelectedIncidentId(incident.id);
    setIncidentDetailOpen(true);
  }

  function handleOpenEditRule(rule: DetectionRuleItem) {
    data.setDialogError(null);
    setSelectedRule(rule);
    setEditRuleOpen(true);
  }

  function handleOpenTerminateSession(sessionId: string) {
    data.setDialogError(null);
    const matched = data.documentSessions.find((s) => s.id === sessionId) ?? null;
    setPendingTerminateSessionSnapshot(matched);
    data.setPendingTerminateSessionId(sessionId);
  }

  async function handleModalSuccess(msg: string) {
    data.setDialogError(null);
    data.setMessage(msg);
    void data.refreshData({ silent: true });
  }

  return (
    <DialogErrorProvider
      errorMessage={data.dialogError}
      onDismiss={() => data.setDialogError(null)}
    >
      <div className="space-y-4">
        <SecurityWorkspaceHeader
          isLoading={data.isLoading}
          message={data.message}
          errorMessage={data.errorMessage}
          canCreateIncident={canCreateIncident}
          onRefresh={() => {
            data.setMessage(null);
            setRefreshSignal((prev) => prev + 1);
            void data.refreshData();
          }}
          onOpenCreateIncident={() => handleOpenCreateIncident()}
        />

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="flex w-full overflow-x-auto no-scrollbar items-center justify-start xl:flex-wrap h-auto min-h-11 xl:min-h-10 rounded-[14px] xl:rounded-[18px] p-1 gap-1 bg-[#ebebeb]/70 xl:bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewAlerts && (
                <TabsTrigger value="alerts" className="shrink-0 flex items-center gap-1.5 text-xs">
                  <AlertOctagon size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Cảnh báo ({data.alertsTotal})</span>
                </TabsTrigger>
              )}
              {canTraceWatermark && (
                <TabsTrigger
                  value="watermark-trace"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Truy vết watermark</span>
                </TabsTrigger>
              )}
              {canViewIncidents && (
                <TabsTrigger
                  value="incidents"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <FileText size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Hồ sơ sự cố ({data.incidentsTotal})</span>
                </TabsTrigger>
              )}
              {canTerminateSession && (
                <TabsTrigger
                  value="sessions"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Phiên đọc ({data.activeSessionsCount})</span>
                </TabsTrigger>
              )}
              {(canViewAlerts || canManageAlerts) && (
                <TabsTrigger
                  value="detection"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <Settings size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Quy tắc phát hiện ({data.detectionRules.length})</span>
                </TabsTrigger>
              )}
              {canViewAlerts && (
                <TabsTrigger
                  value="network-dlp"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <Network size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Giám sát DLP mạng ({data.dlpAlertsTotal})</span>
                </TabsTrigger>
              )}
              {canViewAudit && (
                <TabsTrigger
                  value="audit-integrity"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <Anchor size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Toàn vẹn &amp; Neo Audit</span>
                </TabsTrigger>
              )}
              {canSimulatePolicy && (
                <TabsTrigger
                  value="policy-simulator"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
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
                  canManageRules={canManageRules}
                  onRunDetection={data.runDetection}
                  onEditRule={handleOpenEditRule}
                />
              </TabsContent>
            )}
            {canTerminateSession && (
              <TabsContent value="sessions" className="space-y-4">
                <ActiveSessionsTab
                  documentSessions={data.documentSessions}
                  totalCount={data.sessionsAllTotal}
                  filteredCount={data.sessionsFilteredTotal}
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
                  dlpPage={data.dlpPage}
                  onDlpPageChange={data.setDlpPage}
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
                  refreshSignal={refreshSignal}
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
            data.setDialogError(null);
            if (!open) {
              setSelectedAlertId(null);
              setSelectedAlertSnapshot(null);
            }
          }}
          alert={selectedAlert}
          canManageAlerts={canManageAlerts}
          canCreateIncident={canCreateIncident}
          onCreateIncidentFromAlert={(prefill) => handleOpenCreateIncident(prefill)}
          onClearError={() => data.setDialogError(null)}
          onOptimisticUpdate={(alertId, patch) => {
            setSelectedAlertSnapshot((prev) =>
              prev && prev.id === alertId
                ? {
                    ...prev,
                    status: patch.status ?? prev.status,
                    resolutionNote:
                      patch.resolutionNote !== undefined
                        ? patch.resolutionNote
                        : prev.resolutionNote,
                    notes: patch.addedNote ? [...(prev.notes ?? []), patch.addedNote] : prev.notes,
                  }
                : prev,
            );
            return data.applyOptimisticAlertUpdate(alertId, patch);
          }}
          onSuccess={handleModalSuccess}
          onError={data.setDialogError}
        />

        <CreateIncidentModal
          open={createIncidentOpen}
          onOpenChange={(open) => {
            setCreateIncidentOpen(open);
            data.setDialogError(null);
            if (!open) setIncidentPrefill(null);
          }}
          alerts={data.alerts}
          prefill={incidentPrefill}
          onClearError={() => data.setDialogError(null)}
          onSuccess={handleModalSuccess}
          onError={data.setDialogError}
        />

        <IncidentDetailModal
          open={incidentDetailOpen}
          onOpenChange={(open) => {
            setIncidentDetailOpen(open);
            data.setDialogError(null);
            if (!open) setSelectedIncidentId(null);
          }}
          incidentId={selectedIncidentId}
          canManageIncidents={canManageIncidents}
          onClearError={() => data.setDialogError(null)}
          onSuccess={handleModalSuccess}
          onError={data.setDialogError}
        />

        <EditDetectionRuleModal
          open={editRuleOpen}
          onOpenChange={(open) => {
            setEditRuleOpen(open);
            data.setDialogError(null);
            if (!open) setSelectedRule(null);
          }}
          rule={selectedRule}
          onClearError={() => data.setDialogError(null)}
          onSuccess={handleModalSuccess}
          onError={data.setDialogError}
        />

        <TerminateSessionModal
          open={data.pendingTerminateSessionId !== null}
          onOpenChange={(open) => {
            data.setDialogError(null);
            if (!open) {
              data.setPendingTerminateSessionId(null);
              setPendingTerminateSessionSnapshot(null);
            }
          }}
          session={pendingTerminateSession}
          isSubmitting={data.terminatingSessionId !== null}
          onConfirm={async (reason) => {
            const ok = await data.terminateSession(reason);
            if (ok) setPendingTerminateSessionSnapshot(null);
            return ok;
          }}
          onError={data.setDialogError}
        />
      </div>
    </DialogErrorProvider>
  );
}
