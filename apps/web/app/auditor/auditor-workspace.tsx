'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCheck,
  Hash,
  Lock,
  QrCode,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAuditorData } from './hooks/use-auditor-data';
import { AuditorAlertDetailModal } from './modals/auditor-alert-detail-modal';
import { AuditorLogDetailModal } from './modals/auditor-log-detail-modal';
import { ExportReportModal } from './modals/export-report-modal';
import { AuditTrailTab } from './tabs/audit-trail-tab';
import { AuditorAlertsTab } from './tabs/auditor-alerts-tab';
import { AuditorWatermarkTraceTab } from './tabs/auditor-watermark-trace-tab';
import { ChainIntegrityTab } from './tabs/chain-integrity-tab';
import { ExportQueueTab } from './tabs/export-queue-tab';
import type { AuditorAlertItem, AuditLogItem } from './types';

/**
 * Thuật toán: Không Gian Kiểm Toán Độc Lập Chỉ Đọc Toàn Diện Theo Ma Trận 5 Quyền RBAC (`AuditorWorkspace`)
 * Mục đích:
 *   - Đảm bảo `useAuditorData()` chỉ khởi chạy sau khi `AuthGuard` xác nhận quyền truy cập cổng `AUDITOR`.
 *   - Kết nối đầy đủ 5 quyền chuẩn (`AUDIT_LOG:VIEW`, `AUDIT_LOG:EXPORT`, `SYSTEM_REPORT:EXPORT`, `SECURITY_ALERT:VIEW`, `WATERMARK_INSTANCE:TRACE`) ở chế độ chỉ đọc nghiêm ngặt, ẩn banner lỗi nền khi modal đang mở và định tuyến nút Thử lại đúng theo ngữ cảnh lỗi.
 */
export function AuditorWorkspace() {
  return (
    <AuthGuard requiredPortal="AUDITOR">
      <AppLayout>
        <AuditorWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function AuditorWorkspaceContent() {
  const { hasPermission } = useAuth();
  const canViewAuditLogs = hasPermission('AUDIT_LOG:VIEW');
  const canExportAuditLogs = hasPermission('AUDIT_LOG:EXPORT');
  const canExportSystemReport = hasPermission('SYSTEM_REPORT:EXPORT');
  const canViewAlerts = hasPermission('SECURITY_ALERT:VIEW');
  const canTraceWatermark = hasPermission('WATERMARK_INSTANCE:TRACE');
  const canExportReports = canExportAuditLogs || canExportSystemReport;
  const canExportSecurityAlerts = canViewAlerts && canExportSystemReport;

  const permittedTabs = [
    canViewAuditLogs ? 'logs' : null,
    canViewAuditLogs ? 'chain-verify' : null,
    canExportReports ? 'export-queue' : null,
    canViewAlerts ? 'security-alerts' : null,
    canTraceWatermark ? 'watermark-trace' : null,
  ].filter((t): t is string => t !== null);

  const [selectedTab, setSelectedTab] = useState('logs');
  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'logs');

  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLogItem | null>(null);
  const [auditDetailOpen, setAuditDetailOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<AuditorAlertItem | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);

  const {
    logs,
    page,
    setPage,
    pageSize,
    setPageSize,
    totalPages,
    totalLogs,
    anchors,
    exportJobs,
    verificationReport,
    verifyPartition,
    setVerifyPartition,
    isLoading,
    downloadingJobId,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    dateRangeError,
    activeFilters,
    outcomeFilter,
    setOutcomeFilter,
    actionFilter,
    setActionFilter,
    partitionFilter,
    setPartitionFilter,
    actorFilter,
    setActorFilter,
    fromDate,
    setFromDate,
    toDate,
    setToDate,
    sortOrder,
    setSortOrder,
    resetFilters,
    isVerifyingChain,
    refreshData,
    verifyHashChain,
    downloadExport,
    retryLastFailedOperation,
    prependExportJob,
  } = useAuditorData();

  const hasOpenDialog = exportModalOpen || auditDetailOpen || alertDetailOpen;

  function handleOpenExportModal() {
    setErrorMessage(null);
    setExportModalOpen(true);
  }

  function handleSelectAuditLog(log: AuditLogItem) {
    setErrorMessage(null);
    setSelectedAuditLog(log);
    setAuditDetailOpen(true);
  }

  function handleSelectAlert(alert: AuditorAlertItem) {
    setErrorMessage(null);
    setSelectedAlert(alert);
    setAlertDetailOpen(true);
  }

  return (
    <DialogErrorProvider errorMessage={errorMessage} onDismiss={() => setErrorMessage(null)}>
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <Badge variant="info">Kiểm toán viên độc lập</Badge>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-1">
              Kiểm toán toàn vẹn và báo cáo tuân thủ
            </h1>
          </div>

          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
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
              onClick={() => refreshData()}
              disabled={isLoading}
            />
            {canExportReports && (
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Xuất báo cáo tuân thủ"
                icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={handleOpenExportModal}
              />
            )}
          </div>
        </div>

        <div
          role="note"
          className="flex items-center gap-2 rounded-[20px] border border-[#008489]/20 bg-[#008489]/5 px-3.5 py-2.5 text-xs text-[#008489]"
        >
          <Lock
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#008489]"
            aria-hidden="true"
          />
          <span className="text-[#222222]">
            <strong className="text-[#008489]">Chế độ chỉ đọc:</strong> Bạn có thể tra cứu nhật ký
            kiểm toán, kiểm chứng chuỗi băm, đối soát cảnh báo/watermark và xuất báo cáo tuân thủ,
            không thể chỉnh sửa dữ liệu nghiệp vụ.
          </span>
        </div>

        {message && !hasOpenDialog && (
          <output className="block">
            <Alert variant="success" aria-live="polite" className="text-xs">
              <CheckCircle2
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#008A05]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{message}</AlertDescription>
            </Alert>
          </output>
        )}

        {errorMessage && !hasOpenDialog && (
          <Alert variant="destructive" role="alert" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <div className="ml-2 flex flex-wrap items-center justify-between gap-2">
              <AlertDescription>{errorMessage}</AlertDescription>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Thử lại"
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => retryLastFailedOperation()}
                disabled={isLoading || isVerifyingChain}
              />
            </div>
          </Alert>
        )}

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-1 sm:grid-cols-2 lg:inline-flex lg:w-auto h-auto min-h-10 rounded-[20px] lg:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewAuditLogs && (
                <TabsTrigger value="logs" className="flex items-center gap-1.5 text-xs">
                  <FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Nhật ký kiểm toán ({totalLogs})</span>
                </TabsTrigger>
              )}
              {canViewAuditLogs && (
                <TabsTrigger value="chain-verify" className="flex items-center gap-1.5 text-xs">
                  <Hash size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Kiểm tra toàn vẹn</span>
                </TabsTrigger>
              )}
              {canExportReports && (
                <TabsTrigger value="export-queue" className="flex items-center gap-1.5 text-xs">
                  <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Lịch sử xuất ({exportJobs.length})</span>
                </TabsTrigger>
              )}
              {canViewAlerts && (
                <TabsTrigger value="security-alerts" className="flex items-center gap-1.5 text-xs">
                  <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Cảnh báo an ninh</span>
                </TabsTrigger>
              )}
              {canTraceWatermark && (
                <TabsTrigger value="watermark-trace" className="flex items-center gap-1.5 text-xs">
                  <QrCode size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Truy vết watermark</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canViewAuditLogs && (
              <TabsContent value="logs" className="space-y-4">
                <AuditTrailTab
                  logs={logs}
                  page={page}
                  pageSize={pageSize}
                  totalPages={totalPages}
                  totalLogs={totalLogs}
                  isLoading={isLoading}
                  outcomeFilter={outcomeFilter}
                  actionFilter={actionFilter}
                  partitionFilter={partitionFilter}
                  actorFilter={actorFilter}
                  fromDate={fromDate}
                  toDate={toDate}
                  sortOrder={sortOrder}
                  dateRangeError={dateRangeError}
                  onPageChange={setPage}
                  onPageSizeChange={setPageSize}
                  onOutcomeFilterChange={setOutcomeFilter}
                  onActionFilterChange={setActionFilter}
                  onPartitionFilterChange={setPartitionFilter}
                  onActorFilterChange={setActorFilter}
                  onFromDateChange={setFromDate}
                  onToDateChange={setToDate}
                  onSortOrderChange={setSortOrder}
                  onResetFilters={resetFilters}
                  onSelectLog={handleSelectAuditLog}
                />
              </TabsContent>
            )}

            {canViewAuditLogs && (
              <TabsContent value="chain-verify" className="space-y-4">
                <ChainIntegrityTab
                  verificationReport={verificationReport}
                  anchors={anchors}
                  verifyPartition={verifyPartition}
                  isVerifyingChain={isVerifyingChain}
                  onVerifyPartitionChange={setVerifyPartition}
                  onVerifyHashChain={() => verifyHashChain()}
                />
              </TabsContent>
            )}

            {canExportReports && (
              <TabsContent value="export-queue" className="space-y-4">
                <ExportQueueTab
                  exportJobs={exportJobs}
                  canExport={canExportReports}
                  downloadingJobId={downloadingJobId}
                  onOpenExportModal={handleOpenExportModal}
                  onDownloadExport={downloadExport}
                />
              </TabsContent>
            )}

            {canViewAlerts && (
              <TabsContent value="security-alerts" className="space-y-4">
                <AuditorAlertsTab onSelectAlert={handleSelectAlert} />
              </TabsContent>
            )}

            {canTraceWatermark && (
              <TabsContent value="watermark-trace" className="space-y-4">
                <AuditorWatermarkTraceTab
                  onClearError={() => setErrorMessage(null)}
                  onMessage={(msg) => {
                    setErrorMessage(null);
                    setMessage(msg);
                  }}
                  onError={(msg) => setErrorMessage(msg, 'general')}
                />
              </TabsContent>
            )}
          </Tabs>
        )}

        <AuditorLogDetailModal
          open={auditDetailOpen}
          onOpenChange={(open) => {
            setAuditDetailOpen(open);
            if (!open) setSelectedAuditLog(null);
          }}
          auditLog={selectedAuditLog}
        />

        <ExportReportModal
          open={exportModalOpen}
          onOpenChange={setExportModalOpen}
          canExportAuditLogs={canExportAuditLogs}
          canExportSystemReport={canExportSystemReport}
          canExportSecurityAlerts={canExportSecurityAlerts}
          activeAuditFilters={activeFilters}
          onClearError={() => setErrorMessage(null)}
          onJobCreated={(job, msg) => {
            prependExportJob(job, msg);
            setSelectedTab('export-queue');
          }}
          onError={(msg) => setErrorMessage(msg, 'exports')}
        />

        {canViewAlerts && (
          <AuditorAlertDetailModal
            open={alertDetailOpen}
            onOpenChange={(open) => {
              setAlertDetailOpen(open);
              if (!open) setSelectedAlert(null);
            }}
            alert={selectedAlert}
          />
        )}
      </div>
    </DialogErrorProvider>
  );
}
