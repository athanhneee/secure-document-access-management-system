'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCheck,
  Hash,
  Lock,
  RefreshCw,
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
import { AuditorLogDetailModal } from './modals/auditor-log-detail-modal';
import { ExportReportModal } from './modals/export-report-modal';
import { AuditTrailTab } from './tabs/audit-trail-tab';
import { ChainIntegrityTab } from './tabs/chain-integrity-tab';
import { ExportQueueTab } from './tabs/export-queue-tab';
import type { AuditLogItem } from './types';

/**
 * Thuật toán: Không Gian Kiểm Toán Chỉ Đọc Cô Lập Sau `AuthGuard` & Lọc Quyền Xuất Báo Cáo (`AuditorWorkspace`)
 * Mục đích:
 *   - Đảm bảo `useAuditorData()` chỉ khởi chạy sau khi `AuthGuard` xác nhận vai trò `AUDITOR`.
 *   - Thực thi nguyên tắc Phân tách Trách nhiệm (SoD) và ẩn nút/thẻ xuất báo cáo nếu tài khoản thiếu quyền `AUDIT_LOG:EXPORT` hoặc `SYSTEM_REPORT:EXPORT`.
 */
export function AuditorWorkspace() {
  return (
    <AuthGuard requiredRole="AUDITOR">
      <AppLayout>
        <AuditorWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function AuditorWorkspaceContent() {
  const { hasPermission } = useAuth();
  const canViewAuditLogs = hasPermission('AUDIT_LOG:VIEW');
  const canExportReports =
    hasPermission('AUDIT_LOG:EXPORT') || hasPermission('SYSTEM_REPORT:EXPORT');

  const permittedTabs = [
    canViewAuditLogs ? 'logs' : null,
    canViewAuditLogs ? 'chain-verify' : null,
    canExportReports ? 'export-queue' : null,
  ].filter((t): t is string => t !== null);

  const [selectedTab, setSelectedTab] = useState('logs');
  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'logs');

  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLogItem | null>(null);
  const [auditDetailOpen, setAuditDetailOpen] = useState(false);

  const {
    logs,
    page,
    setPage,
    pageSize,
    setPageSize,
    totalPages,
    totalLogs,
    exportJobs,
    verificationReport,
    isLoading,
    message,
    errorMessage,
    setErrorMessage,
    outcomeFilter,
    setOutcomeFilter,
    actionFilter,
    setActionFilter,
    fromDate,
    setFromDate,
    toDate,
    setToDate,
    isVerifyingChain,
    refreshData,
    verifyHashChain,
    downloadExport,
    prependExportJob,
  } = useAuditorData();

  function handleOpenExportModal() {
    setErrorMessage(null);
    setExportModalOpen(true);
  }

  function handleSelectAuditLog(log: AuditLogItem) {
    setErrorMessage(null);
    setSelectedAuditLog(log);
    setAuditDetailOpen(true);
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
              onClick={() => void refreshData()}
              disabled={isLoading}
            />
            {canExportReports && (
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Xuất báo cáo kiểm toán"
                icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={handleOpenExportModal}
              />
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 rounded-[16px] border border-[#008489]/20 bg-[#008489]/5 px-3.5 py-2 text-xs text-[#008489]">
          <Lock
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#008489]"
            aria-hidden="true"
          />
          <span className="text-[#222222]">
            <strong className="text-[#008489]">Chế độ chỉ đọc:</strong> Bạn có thể tra cứu nhật ký
            kiểm toán, kiểm tra tính toàn vẹn và xuất báo cáo tuân thủ, không thể chỉnh sửa dữ liệu
            nghiệp vụ.
          </span>
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
            <div className="ml-2 flex flex-wrap items-center justify-between gap-2">
              <AlertDescription>{errorMessage}</AlertDescription>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Thử lại"
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => void refreshData()}
                disabled={isLoading}
              />
            </div>
          </Alert>
        )}

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-1 sm:grid-cols-3 lg:inline-flex lg:w-auto h-auto min-h-10 rounded-[18px] lg:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
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
                  <span>Lịch sử xuất báo cáo ({exportJobs.length})</span>
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
                  fromDate={fromDate}
                  toDate={toDate}
                  onPageChange={setPage}
                  onPageSizeChange={setPageSize}
                  onOutcomeFilterChange={setOutcomeFilter}
                  onActionFilterChange={setActionFilter}
                  onFromDateChange={setFromDate}
                  onToDateChange={setToDate}
                  onSelectLog={handleSelectAuditLog}
                />
              </TabsContent>
            )}

            {canViewAuditLogs && (
              <TabsContent value="chain-verify" className="space-y-4">
                <ChainIntegrityTab
                  verificationReport={verificationReport}
                  isVerifyingChain={isVerifyingChain}
                  onVerifyHashChain={() => void verifyHashChain()}
                />
              </TabsContent>
            )}

            {canExportReports && (
              <TabsContent value="export-queue" className="space-y-4">
                <ExportQueueTab
                  exportJobs={exportJobs}
                  canExport={canExportReports}
                  onOpenExportModal={handleOpenExportModal}
                  onDownloadExport={(job) => void downloadExport(job)}
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
          onClearError={() => setErrorMessage(null)}
          onJobCreated={prependExportJob}
          onError={setErrorMessage}
        />
      </div>
    </DialogErrorProvider>
  );
}
