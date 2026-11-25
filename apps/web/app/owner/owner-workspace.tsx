'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileUp,
  FolderLock,
  History,
  KeyRound,
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
import { filterOwnerDocuments } from './helpers';
import { useDocumentHistory } from './hooks/use-document-history';
import { useDocumentLifecycle } from './hooks/use-document-lifecycle';
import { useOwnerData, type OwnerTab } from './hooks/use-owner-data';
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
 * Thuật toán: Không Gian Chủ Sở Hữu Cô Lập Sau `AuthGuard` & Lọc Thao Tác Theo Quyền Hạt Mịn (`OwnerWorkspace`)
 * Mục đích:
 *   - Chặn toàn bộ hook dữ liệu (`useOwnerData`) chạy trước khi `AuthGuard` xác nhận vai trò `DOCUMENT_OWNER`.
 *   - Ẩn hoàn toàn các thẻ tab và nút thao tác không thuộc tập quyền hiệu lực của tài khoản.
 */
export function OwnerWorkspace() {
  return (
    <AuthGuard requiredRole="DOCUMENT_OWNER">
      <AppLayout>
        <OwnerWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function OwnerWorkspaceContent() {
  const { user, hasPermission } = useAuth();

  const canUpload = hasPermission('DOCUMENT:UPLOAD');
  const canManageDoc = hasPermission('DOCUMENT:MANAGE');
  const canViewDoc = hasPermission('DOCUMENT:VIEW');
  const canDownloadDoc = hasPermission('DOCUMENT:DOWNLOAD');
  const canCreateVersion = hasPermission('DOCUMENT_VERSION:CREATE');
  const canClassifyDoc = hasPermission('DOCUMENT:CLASSIFY');
  const canArchiveDoc = hasPermission('DOCUMENT:ARCHIVE');
  const canDecideRequest = hasPermission('ACCESS_REQUEST:DECIDE');
  const canViewRequests = canDecideRequest || hasPermission('ACCESS_REQUEST:VIEW_OWN');
  const canCreateGrant = hasPermission('ACCESS_GRANT:CREATE');
  const canRevokeGrant = hasPermission('ACCESS_GRANT:REVOKE');
  const canViewGrants = hasPermission('ACCESS_GRANT:VIEW') || canCreateGrant || canRevokeGrant;
  const canViewHistory = hasPermission('AUDIT_LOG:VIEW');
  const canViewDocsTab =
    hasPermission('DOCUMENT:DISCOVER') || canViewDoc || canManageDoc || canUpload;

  const permittedTabs: OwnerTab[] = [
    canViewDocsTab ? ('documents' as const) : null,
    canViewRequests ? ('requests' as const) : null,
    canViewGrants ? ('grants' as const) : null,
    canViewHistory ? ('history' as const) : null,
  ].filter((t): t is OwnerTab => t !== null);

  const [selectedTab, setSelectedTab] = useState<OwnerTab>('documents');
  const activeTab: OwnerTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'documents');
  const [searchQuery, setSearchQuery] = useState('');

  const data = useOwnerData(activeTab);
  const delivery = useOwnerDelivery({
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const uploadWizard = useUploadWizard({
    userDepartmentId: user?.departmentId,
    userClearanceRank: user?.clearanceRank,
    departments: data.departments,
    businessCategories: data.businessCategories,
    classificationLevels: data.classificationLevels,
    ensureUploadLookups: data.ensureUploadLookups,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const clearError = () => data.setErrorMessage(null);
  const lifecycle = useDocumentLifecycle({
    setDocuments: data.setDocuments,
    classificationLevels: data.classificationLevels,
    businessCategories: data.businessCategories,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const history = useDocumentHistory(clearError);
  const grantsControl = useOwnerGrants({
    currentUserId: user?.id,
    documents: data.documents,
    setGrants: data.setGrants,
    setActiveGrantsCount: data.setActiveGrantsCount,
    usersLookup: data.usersLookup,
    rolesLookup: data.rolesLookup,
    ensureGrantLookups: data.ensureGrantLookups,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const requestsControl = useOwnerRequests({
    setRequests: data.setRequests,
    onRequestApproved: data.invalidateGrants,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });

  const filteredDocs = filterOwnerDocuments(data.documents, searchQuery);
  const pendingCount = data.requests.filter((r) => r.status === 'PENDING').length;
  const activeGrantCount = data.activeGrantsCount;

  return (
    <DialogErrorProvider
      errorMessage={data.errorMessage}
      onDismiss={() => data.setErrorMessage(null)}
    >
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <Badge variant="warning">Chủ sở hữu tài liệu</Badge>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
              Quản lý và cấp quyền tài liệu mật
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
                  className={data.isLoading ? 'animate-spin' : ''}
                  aria-hidden="true"
                />
              }
              onClick={() => void data.refreshData()}
              disabled={data.isLoading}
            />
            {canUpload && (
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Tải lên tài liệu mới"
                icon={<FileUp size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={uploadWizard.openUploadWizard}
              />
            )}
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

        {permittedTabs.length > 0 && (
          <Tabs
            value={activeTab}
            onValueChange={(value) => setSelectedTab(value as OwnerTab)}
            className="space-y-3.5"
          >
            <TabsList className="grid w-full grid-cols-2 lg:inline-flex lg:w-auto h-auto min-h-10 rounded-[18px] lg:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewDocsTab && (
                <TabsTrigger value="documents" className="flex items-center gap-1.5 text-xs">
                  <FolderLock size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.documents
                      ? `Tài liệu quản lý (${data.documents.length})`
                      : 'Tài liệu quản lý'}
                  </span>
                </TabsTrigger>
              )}
              {canViewRequests && (
                <TabsTrigger value="requests" className="flex items-center gap-1.5 text-xs">
                  <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.requests
                      ? `Yêu cầu cần duyệt (${pendingCount})`
                      : 'Yêu cầu cần duyệt'}
                  </span>
                </TabsTrigger>
              )}
              {canViewGrants && (
                <TabsTrigger value="grants" className="flex items-center gap-1.5 text-xs">
                  <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.grants
                      ? `Quyền truy cập (${activeGrantCount})`
                      : 'Quyền truy cập'}
                  </span>
                </TabsTrigger>
              )}
              {canViewHistory && (
                <TabsTrigger value="history" className="flex items-center gap-1.5 text-xs">
                  <History size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Lịch sử truy cập</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canViewDocsTab && (
              <TabsContent value="documents" className="space-y-4">
                <DocumentsTab
                  documents={filteredDocs}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  isLoadingPreview={delivery.isLoadingPreview}
                  downloadingDocId={delivery.downloadingDocId}
                  canManage={canManageDoc}
                  canView={canViewDoc}
                  canDownload={canDownloadDoc}
                  canCreateVersion={canCreateVersion}
                  canClassify={canClassifyDoc}
                  canArchive={canArchiveDoc}
                  onActivate={(doc) => void lifecycle.handleActivateDocument(doc)}
                  onOpenPreview={(doc) => void delivery.handleOpenPreview(doc)}
                  onDownload={(doc) => void delivery.handleDownloadWithTicket(doc)}
                  onOpenNewVersion={lifecycle.openNewVersionModal}
                  onOpenReclassify={lifecycle.openReclassifyModal}
                  onOpenArchive={lifecycle.openArchiveModal}
                  onOpenVersionHistory={(doc) => void history.handleOpenVersionHistory(doc)}
                />
              </TabsContent>
            )}
            {canViewRequests && (
              <TabsContent value="requests" className="space-y-4">
                <RequestsTab
                  requests={data.requests}
                  canDecideRequest={canDecideRequest}
                  onOpenApprove={requestsControl.openApproveModal}
                  onReject={requestsControl.handleRejectRequest}
                  onClearError={clearError}
                />
              </TabsContent>
            )}
            {canViewGrants && (
              <TabsContent value="grants" className="space-y-4">
                <GrantsTab
                  grants={data.grants}
                  activeGrantCount={activeGrantCount}
                  grantsPage={data.grantsPage}
                  grantsHasMore={data.grantsHasMore}
                  grantsStatusFilter={data.grantsStatusFilter}
                  isLoadingGrants={data.isLoadingGrants}
                  canCreateGrant={canCreateGrant}
                  canRevokeGrant={canRevokeGrant}
                  onChangeStatusFilter={(status) => void data.loadGrants(1, status)}
                  onLoadPage={(page) => void data.loadGrants(page, data.grantsStatusFilter)}
                  onOpenDirectGrant={grantsControl.openDirectGrantModal}
                  onOpenRevoke={grantsControl.openRevokeModal}
                />
              </TabsContent>
            )}
            {canViewHistory && (
              <TabsContent value="history" className="space-y-4">
                <AuditHistoryTab
                  auditLogs={data.auditLogs}
                  auditPage={data.auditPage}
                  auditTotalPages={data.auditTotalPages}
                  auditTotal={data.auditTotal}
                  isLoadingAudit={data.isLoadingAudit}
                  onLoadPage={(page) => void data.loadAuditLogs(page)}
                  onInspectLog={(log) => {
                    clearError();
                    data.setSelectedAuditLog(log);
                    data.setAuditDetailOpen(true);
                  }}
                />
              </TabsContent>
            )}
          </Tabs>
        )}

        <UploadDocumentModal
          wizard={uploadWizard}
          departments={data.departments}
          businessCategories={data.businessCategories}
          classificationLevels={data.classificationLevels}
          userClearanceRank={user?.clearanceRank}
          userClearanceCode={user?.clearanceCode}
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
          rolesLookup={data.rolesLookup}
          auditDetailOpen={data.auditDetailOpen}
          onAuditDetailOpenChange={data.setAuditDetailOpen}
          selectedAuditLog={data.selectedAuditLog}
          userFullName={user?.fullName}
          username={user?.username}
        />
      </div>
    </DialogErrorProvider>
  );
}
