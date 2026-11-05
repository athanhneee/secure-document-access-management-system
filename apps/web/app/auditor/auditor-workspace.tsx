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
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAuditorData } from './hooks/use-auditor-data';
import { ExportReportModal } from './modals/export-report-modal';
import { AuditTrailTab } from './tabs/audit-trail-tab';
import { ChainIntegrityTab } from './tabs/chain-integrity-tab';
import { ExportQueueTab } from './tabs/export-queue-tab';

/**
 * Thuật toán: Không gian Kiểm toán Chỉ đọc & Xác minh Toàn vẹn Chuỗi Băm (Read-Only Auditor & Cryptographic Chain Verifier)
 * Mục đích: Đảm bảo nguyên tắc Phân tách Trách nhiệm (Separation of Duties - SoD), cho phép kiểm toán viên tra cứu vết hoạt động bất biến, xác minh chuỗi băm HMAC-SHA256 và xuất báo cáo tuân thủ.
 * Cơ chế hoạt động:
 *   - Truy vấn phân trang nhật ký chỉ thêm (`append-only`), tổng hợp báo cáo đối chiếu chuỗi băm đa phân vùng và điều phối hàng đợi xuất tệp có khử độc công thức bảng tính (CSV Formula Injection).
 */
export function AuditorWorkspace() {
  const [activeTab, setActiveTab] = useState('logs');
  const [exportModalOpen, setExportModalOpen] = useState(false);

  const {
    logs,
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

  return (
    <AuthGuard requiredRole="AUDITOR">
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="info">Auditor (Read-Only)</Badge>
                <span className="text-xs text-[#717171]">Phân tách Trách nhiệm (SoD)</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Kiểm toán Toàn vẹn &amp; Báo cáo Tuân thủ
              </h1>
              <p className="text-xs text-[#717171]">
                Chế độ chỉ đọc nghiêm ngặt. Xác minh chuỗi băm HMAC-SHA256 và xuất dữ liệu có chống
                Formula Injection
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
                text="Xuất báo cáo kiểm toán"
                icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => setExportModalOpen(true)}
              />
            </div>
          </div>

          <div className="flex items-center gap-2.5 rounded-[20px] border border-[#008489]/20 bg-[#008489]/5 px-3.5 py-2.5 text-xs text-[#008489]">
            <Lock
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#008489]"
              aria-hidden="true"
            />
            <span className="text-[#222222]">
              <strong className="text-[#008489]">Nguyên tắc Phân tách Trách nhiệm (SoD):</strong>{' '}
              Kiểm toán viên chỉ có quyền xem nhật ký và xuất báo cáo. Không được phép chỉnh sửa kết
              luận điều tra sự cố hoặc can thiệp cấp quyền tài liệu.
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
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-3 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger value="logs" className="flex items-center gap-1.5 text-xs">
                <FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Nhật ký kiểm toán ({logs.length})</span>
              </TabsTrigger>
              <TabsTrigger value="chain-verify" className="flex items-center gap-1.5 text-xs">
                <Hash size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xác minh chuỗi băm HMAC</span>
              </TabsTrigger>
              <TabsTrigger value="export-queue" className="flex items-center gap-1.5 text-xs">
                <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Hàng đợi báo cáo ({exportJobs.length})</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="logs" className="space-y-4">
              <AuditTrailTab
                logs={logs}
                outcomeFilter={outcomeFilter}
                actionFilter={actionFilter}
                fromDate={fromDate}
                toDate={toDate}
                onOutcomeFilterChange={setOutcomeFilter}
                onActionFilterChange={setActionFilter}
                onFromDateChange={setFromDate}
                onToDateChange={setToDate}
              />
            </TabsContent>

            <TabsContent value="chain-verify" className="space-y-4">
              <ChainIntegrityTab
                verificationReport={verificationReport}
                isVerifyingChain={isVerifyingChain}
                onVerifyHashChain={() => void verifyHashChain()}
              />
            </TabsContent>

            <TabsContent value="export-queue" className="space-y-4">
              <ExportQueueTab
                exportJobs={exportJobs}
                onOpenExportModal={() => setExportModalOpen(true)}
                onDownloadExport={(job) => void downloadExport(job)}
              />
            </TabsContent>
          </Tabs>

          <ExportReportModal
            open={exportModalOpen}
            onOpenChange={setExportModalOpen}
            onClearError={() => setErrorMessage(null)}
            onJobCreated={prependExportJob}
            onError={setErrorMessage}
          />
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
