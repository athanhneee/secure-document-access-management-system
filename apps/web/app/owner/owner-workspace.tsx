'use client';

import { useState } from 'react';
import {
  FileUp,
  FolderLock,
  Clock,
  KeyRound,
  History,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { filterOwnerDocuments } from './helpers';
import { useDocumentHistory } from './hooks/use-document-history';
import { useDocumentLifecycle } from './hooks/use-document-lifecycle';
import { useOwnerData } from './hooks/use-owner-data';
import { useOwnerDelivery } from './hooks/use-owner-delivery';
import { useOwnerGrants } from './hooks/use-owner-grants';
import { useOwnerRequests } from './hooks/use-owner-requests';
import { useUploadWizard } from './hooks/use-upload-wizard';
import { AccessAndAuditModals } from './modals/access-and-audit-modals';
import { DocumentLifecycleModals } from './modals/document-lifecycle-modals';
import { UploadDocumentModal } from './modals/upload-document-modal';
import { AuditHistoryTab } from './tabs/audit-history-tab';
import { DocumentsTab } from './tabs/documents-tab';
import { GrantsTab } from './tabs/grants-tab';
import { RequestsTab } from './tabs/requests-tab';

/**
 * Thuật toán: Không gian Điều phối Vòng đời Tài liệu Mật & Cấp phép Chủ sở hữu (`OwnerWorkspace`)
 * Mục đích: Tích hợp quy trình tải lên đa bước có phân loại mật bắt buộc, xét duyệt yêu cầu, cấp/thu hồi quyền trực tiếp và phân phối tài liệu gắn thủy vân.
 * Cơ chế hoạt động:
 *   - Kết hợp các hook miền chuyên biệt (`useOwnerData`, `useOwnerDelivery`, `useUploadWizard`, `useDocumentLifecycle`, `useOwnerGrants`, `useOwnerRequests`) dưới cổng bảo vệ `AuthGuard` (`DOCUMENT_OWNER`).
 */
export function OwnerWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('documents');
  const [searchQuery, setSearchQuery] = useState('');

  const data = useOwnerData();
  const delivery = useOwnerDelivery({
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const uploadWizard = useUploadWizard({
    userDepartmentId: user?.departmentId,
    departments: data.departments,
    businessCategories: data.businessCategories,
    classificationLevels: data.classificationLevels,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const lifecycle = useDocumentLifecycle({
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const history = useDocumentHistory();
  const grantsControl = useOwnerGrants({
    documents: data.documents,
    usersLookup: data.usersLookup,
    rolesLookup: data.rolesLookup,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const requestsControl = useOwnerRequests({
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });

  const filteredDocs = filterOwnerDocuments(data.documents, searchQuery);

  return (
    <AuthGuard requiredRole="DOCUMENT_OWNER">
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="warning">Document Owner</Badge>
                <span className="text-xs text-[#717171]">Phân hệ Chủ sở hữu</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Quản lý & Cấp phép Tài liệu Mật
              </h1>
              <p className="text-xs text-[#717171]">
                Tải lên tệp đa phương thức với kiểm tra phân loại bắt buộc, cấp quyền trực tiếp, xét
                duyệt và quản lý toàn diện vòng đời tài liệu
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
                text="Tải lên tài liệu mới"
                icon={<FileUp size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={uploadWizard.openUploadWizard}
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
              <AlertDescription className="ml-2">{data.errorMessage}</AlertDescription>
            </Alert>
          )}

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger value="documents" className="flex items-center gap-1.5 text-xs">
                <FolderLock size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Tài liệu sở hữu ({data.documents.length})</span>
              </TabsTrigger>
              <TabsTrigger value="requests" className="flex items-center gap-1.5 text-xs">
                <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>
                  Yêu cầu cần duyệt ({data.requests.filter((r) => r.status === 'PENDING').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="grants" className="flex items-center gap-1.5 text-xs">
                <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>
                  Giấy phép hiệu lực ({data.grants.filter((g) => g.status === 'ACTIVE').length})
                </span>
              </TabsTrigger>
              <TabsTrigger value="history" className="flex items-center gap-1.5 text-xs">
                <History size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Lịch sử truy cập</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="documents" className="space-y-4">
              <DocumentsTab
                documents={filteredDocs}
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                isLoadingPreview={delivery.isLoadingPreview}
                downloadingDocId={delivery.downloadingDocId}
                onActivate={(doc) => void lifecycle.handleActivateDocument(doc)}
                onOpenPreview={(doc) => void delivery.handleOpenPreview(doc)}
                onDownload={(doc) => void delivery.handleDownloadWithTicket(doc)}
                onOpenNewVersion={lifecycle.openNewVersionModal}
                onOpenReclassify={lifecycle.openReclassifyModal}
                onOpenArchive={lifecycle.openArchiveModal}
                onOpenVersionHistory={(doc) => void history.handleOpenVersionHistory(doc)}
              />
            </TabsContent>

            <TabsContent value="requests" className="space-y-4">
              <RequestsTab
                requests={data.requests}
                onOpenApprove={requestsControl.openApproveModal}
                onReject={(req) => void requestsControl.handleRejectRequest(req)}
              />
            </TabsContent>

            <TabsContent value="grants" className="space-y-4">
              <GrantsTab
                grants={data.grants}
                onOpenDirectGrant={grantsControl.openDirectGrantModal}
                onOpenRevoke={grantsControl.openRevokeModal}
              />
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <AuditHistoryTab
                auditLogs={data.auditLogs}
                auditPage={data.auditPage}
                auditTotalPages={data.auditTotalPages}
                auditTotal={data.auditTotal}
                isLoadingAudit={data.isLoadingAudit}
                onLoadPage={(page) => void data.loadAuditLogs(page)}
                onInspectLog={(log) => {
                  data.setSelectedAuditLog(log);
                  data.setAuditDetailOpen(true);
                }}
              />
            </TabsContent>
          </Tabs>

          <UploadDocumentModal
            wizard={uploadWizard}
            departments={data.departments}
            businessCategories={data.businessCategories}
            classificationLevels={data.classificationLevels}
          />
          <DocumentLifecycleModals
            lifecycle={lifecycle}
            history={history}
            classificationLevels={data.classificationLevels}
            businessCategories={data.businessCategories}
          />
          <AccessAndAuditModals
            grantsControl={grantsControl}
            requestsControl={requestsControl}
            delivery={delivery}
            documents={data.documents}
            usersLookup={data.usersLookup}
            rolesLookup={data.rolesLookup}
            auditDetailOpen={data.auditDetailOpen}
            onAuditDetailOpenChange={data.setAuditDetailOpen}
            selectedAuditLog={data.selectedAuditLog}
            userFullName={user?.fullName}
            username={user?.username}
          />
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
