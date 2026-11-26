'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileUp,
  FolderLock,
  History,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useAuth, type AuthUser } from '@/lib/auth-context';
import { useSessionPosture } from '@/lib/use-session-posture';
import { useWorkspaceTabSync } from '@/lib/use-workspace-tab-sync';
import { AuthGuard } from '@/components/auth-guard';
import { SessionPostureBanner } from '@/components/documents/session-posture-banner';
import { AppLayout } from '@/components/navigation/app-layout';
import { WORKSPACE_TAB_EVENT } from '@/components/navigation/notification-bell-dialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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

type ExtendedUploadAuthUser = AuthUser & {
  hasGlobalDocumentUpload?: boolean | undefined;
  documentUploadDepartmentIds?: string[] | undefined;
};

/**
 * Thuật toán: Không Gian Chủ Sở Hữu Cô Lập Sau `AuthGuard`, Đồng Bộ `?tab=` Hai Chiều & Cô Lập Lỗi Hộp Thoại (`OwnerWorkspace`, BUG-090, BUG-099, BUG-101, BUG-102, BUG-120)
 * Mục đích:
 *   - Chặn toàn bộ hook dữ liệu (`useOwnerData`) chạy trước khi `AuthGuard` xác nhận vai trò `DOCUMENT_OWNER`.
 *   - Đồng bộ tham số `?tab=` qua `useWorkspaceTabSync` kèm lắng nghe `WORKSPACE_TAB_EVENT`, tách riêng `dialogError` của modal và `errorMessage` của trang.
 */
export function OwnerWorkspace() {
  return (
    <AuthGuard requiredPortal="DOCUMENT_OWNER">
      <AppLayout>
        <Suspense fallback={null}>
          <OwnerWorkspaceContent />
        </Suspense>
      </AppLayout>
    </AuthGuard>
  );
}

function OwnerWorkspaceContent() {
  const { user, hasPermission } = useAuth();
  const searchParams = useSearchParams();
  const scopedUser = user as ExtendedUploadAuthUser | null;

  const canUpload = hasPermission('DOCUMENT:UPLOAD');
  const canManageDoc = hasPermission('DOCUMENT:MANAGE');
  const canViewDoc = hasPermission('DOCUMENT:VIEW');
  const canDownloadDoc = hasPermission('DOCUMENT:DOWNLOAD');
  const canCreateVersion = canUpload && hasPermission('DOCUMENT_VERSION:CREATE');
  const canClassifyDoc = hasPermission('DOCUMENT:CLASSIFY');
  const canArchiveDoc = hasPermission('DOCUMENT:ARCHIVE');
  const canDecideRequest = hasPermission('ACCESS_REQUEST:DECIDE');
  const canViewRequests = canDecideRequest;
  const canCreateGrant = hasPermission('ACCESS_GRANT:CREATE');
  const canRevokeGrant = hasPermission('ACCESS_GRANT:REVOKE');
  const canViewGrants = hasPermission('ACCESS_GRANT:VIEW');
  const canViewHistory = hasPermission('AUDIT_LOG:VIEW');
  const canViewDocsTab = hasPermission('DOCUMENT:DISCOVER');

  const permittedTabs = useMemo<OwnerTab[]>(
    () =>
      [
        canViewDocsTab ? ('documents' as const) : null,
        canViewRequests ? ('requests' as const) : null,
        canViewGrants ? ('grants' as const) : null,
        canViewHistory ? ('history' as const) : null,
      ].filter((t): t is OwnerTab => t !== null),
    [canViewDocsTab, canViewGrants, canViewHistory, canViewRequests],
  );

  const [syncedTab, setSyncedTab] = useWorkspaceTabSync<OwnerTab>(permittedTabs, 'documents');

  useEffect(() => {
    function handleTabSync(event: Event) {
      const detail = (event as CustomEvent<{ path?: string; tab?: string }>).detail;
      if (
        detail?.path === '/owner' &&
        detail.tab &&
        permittedTabs.includes(detail.tab as OwnerTab)
      ) {
        setSyncedTab(detail.tab as OwnerTab);
      }
    }
    window.addEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
    return () => window.removeEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
  }, [permittedTabs, setSyncedTab]);

  const activeTab: OwnerTab | null = permittedTabs.length === 0 ? null : syncedTab;
  const [searchQuery, setSearchQuery] = useState('');

  const data = useOwnerData(activeTab, searchQuery);
  const { posture, refreshPosture } = useSessionPosture(Boolean(user));
  const delivery = useOwnerDelivery({
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
  });
  const uploadWizard = useUploadWizard({
    userDepartmentId: user?.departmentId,
    userClearanceRank: user?.clearanceRank,
    userStatus: user?.status,
    hasGlobalDocumentUpload: scopedUser?.hasGlobalDocumentUpload,
    documentUploadDepartmentIds: scopedUser?.documentUploadDepartmentIds,
    canCreateVersion,
    canClassify: canClassifyDoc,
    departments: data.departments,
    businessCategories: data.businessCategories,
    classificationLevels: data.classificationLevels,
    ensureUploadLookups: data.ensureUploadLookups,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setDialogError: data.setDialogError,
  });
  const clearPageError = () => data.setErrorMessage(null);
  const history = useDocumentHistory(data.setDialogError);
  const grantsControl = useOwnerGrants({
    currentUserId: user?.id,
    documents: data.documents,
    activeDocuments: data.activeOwnedDocuments,
    isLoadingGrantDocs: data.isLoadingGrantDocs,
    grantsPage: data.grantsPage,
    grantsCountOnPage: data.grants.length,
    grantsStatusFilter: data.grantsStatusFilter,
    onLoadGrantsPage: (page, status) => data.loadGrants(page, status),
    setGrants: data.setGrants,
    setActiveGrantsCount: data.setActiveGrantsCount,
    usersLookup: data.usersLookup,
    rolesLookup: data.rolesLookup,
    ensureGrantLookups: data.ensureGrantLookups,
    ensureGrantDocuments: data.ensureGrantDocuments,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setDialogError: data.setDialogError,
  });
  const lifecycle = useDocumentLifecycle({
    setDocuments: data.setDocuments,
    departments: uploadWizard.permittedDepartments,
    classificationLevels: data.classificationLevels,
    businessCategories: data.businessCategories,
    eligibleTransferUsers: grantsControl.eligibleUsers,
    userClearanceRank: user?.clearanceRank,
    ensureUploadLookups: data.ensureUploadLookups,
    ensureGrantLookups: data.ensureGrantLookups,
    onVersionPromoted: history.updateDocForVersionsCurrentNo,
    invalidateGrants: data.invalidateGrants,
    refreshData: data.refreshData,
    setMessage: data.setMessage,
    setErrorMessage: data.setErrorMessage,
    setDialogError: data.setDialogError,
  });
  const requestsControl = useOwnerRequests({
    documents: data.documents,
    requestsPage: data.requestsPage,
    requestsCountOnPage: data.requests.length,
    onLoadRequestsPage: (page) => data.loadRequestsPage(page),
    setRequests: data.setRequests,
    setRequestsTotal: data.setRequestsTotal,
    onRequestApproved: data.invalidateGrants,
    setMessage: data.setMessage,
    setDialogError: data.setDialogError,
  });

  const filteredDocs = data.documents;
  const pendingCount = data.loadedTabs.requests
    ? data.requestsTotal
    : data.requests.filter((r) => r.status === 'PENDING').length;
  const activeGrantCount = data.activeGrantsCount;
  const effectiveMfaEnabled = posture?.mfaEnabled ?? user?.mfaEnabled;
  const tabQuery = searchParams.get('tab');
  const redirectTarget = tabQuery ? `/owner?tab=${encodeURIComponent(tabQuery)}` : '/owner';
  const encodedRedirect = encodeURIComponent(redirectTarget);
  const mfaActionHref = effectiveMfaEnabled
    ? `/mfa?redirect=${encodedRedirect}`
    : `/mfa?enroll=1&method=totp&redirect=${encodedRedirect}`;
  const hasTopSecretDocs = data.documents.some((d) => d.classificationCode === 'TOP_SECRET');

  return (
    <DialogErrorProvider
      errorMessage={data.dialogError}
      onDismiss={() => data.setDialogError(null)}
    >
      <div className="space-y-3.5 sm:space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 sm:gap-3">
          <div className="flex items-start justify-between gap-3 sm:block min-w-0">
            <div className="min-w-0">
              <Badge variant="warning" className="hidden sm:inline-flex">
                Chủ sở hữu tài liệu
              </Badge>
              <h1 className="text-lg sm:text-2xl font-bold tracking-tight text-[#222222] sm:mt-0.5 leading-snug">
                Quản lý và cấp quyền tài liệu mật
              </h1>
            </div>
            <button
              type="button"
              onClick={() => {
                delivery.clearMfaActionRequired();
                void refreshPosture();
                void data.refreshData();
              }}
              disabled={data.isLoading}
              aria-label="Làm mới"
              title="Làm mới dữ liệu"
              className="flex sm:hidden h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
            >
              <RefreshCw
                size={16}
                strokeWidth={1.75}
                className={data.isLoading ? 'animate-spin' : ''}
                aria-hidden="true"
              />
            </button>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="hidden sm:inline-flex">
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
                onClick={() => {
                  delivery.clearMfaActionRequired();
                  void refreshPosture();
                  return data.refreshData();
                }}
                disabled={data.isLoading}
              />
            </span>
            {canUpload && (
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Tải lên tài liệu mới"
                icon={<FileUp size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={uploadWizard.openUploadWizard}
                className="w-full sm:w-auto"
              />
            )}
          </div>
        </div>

        <SessionPostureBanner
          posture={posture}
          mfaActionHref={mfaActionHref}
          userClearanceRank={user?.clearanceRank}
          hasTopSecretDocuments={hasTopSecretDocs}
          suppressProactiveAlert={Boolean(data.errorMessage)}
        />

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
            <div className="ml-2 flex flex-col gap-2 w-full">
              <div className="flex items-start justify-between gap-2">
                <AlertDescription>{data.errorMessage}</AlertDescription>
                <button
                  type="button"
                  onClick={() => {
                    data.setErrorMessage(null);
                    delivery.clearMfaActionRequired();
                  }}
                  aria-label="Đóng thông báo lỗi"
                  className="shrink-0 flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#C13515] hover:bg-[#C13515]/10 cursor-pointer"
                >
                  <X size={16} strokeWidth={2} aria-hidden="true" />
                </button>
              </div>
              {delivery.mfaActionRequired && (
                <div>
                  <Link
                    href={mfaActionHref}
                    className="inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full bg-[#FF385C] px-3.5 py-1.5 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors"
                  >
                    <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>
                      {effectiveMfaEnabled ? 'Xác thực MFA ngay' : 'Thiết lập MFA (TOTP / Passkey)'}
                    </span>
                  </Link>
                </div>
              )}
            </div>
          </Alert>
        )}

        {permittedTabs.length === 0 || !activeTab ? (
          <Card>
            <CardContent className="py-10 px-4 text-center space-y-2.5">
              <div className="flex justify-center text-[#717171]">
                <Lock size={24} strokeWidth={1.75} aria-hidden="true" />
              </div>
              <p className="text-sm font-semibold text-[#222222]">
                {canUpload
                  ? 'Tài khoản được phép tải lên tài liệu mới'
                  : 'Chưa có bảng danh sách quản lý nào được cấp quyền xem'}
              </p>
              <p className="text-xs text-[#717171] max-w-md mx-auto leading-relaxed">
                {canUpload
                  ? 'Bạn có thể sử dụng nút "Tải lên tài liệu mới" ở góc trên để tiếp nhận tài liệu. Để xem danh sách kho tài liệu, yêu cầu duyệt hoặc quyền đã cấp, vui lòng liên hệ quản trị viên cấp thêm quyền tra cứu tương ứng.'
                  : 'Tài khoản hiện chưa có quyền tra cứu danh sách tài liệu, yêu cầu truy cập hoặc lịch sử kiểm toán. Vui lòng liên hệ quản trị viên để được cấp quyền phù hợp.'}
              </p>
              {canCreateGrant && (
                <div className="pt-1 flex justify-center">
                  <InteractiveHoverButton
                    variant="secondary"
                    size="sm"
                    text="Cấp quyền trực tiếp"
                    icon={<KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={grantsControl.openDirectGrantModal}
                  />
                </div>
              )}
            </CardContent>
          </Card>
        ) : (
          <Tabs
            value={activeTab}
            onValueChange={(value) => setSyncedTab(value as OwnerTab)}
            className="space-y-3.5"
          >
            <TabsList className="flex w-full overflow-x-auto no-scrollbar items-center justify-start lg:inline-flex lg:w-auto h-auto min-h-11 lg:min-h-10 rounded-[14px] lg:rounded-full p-1 gap-1 bg-[#ebebeb]/70 lg:bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canViewDocsTab && (
                <TabsTrigger
                  value="documents"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <FolderLock size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.documents
                      ? `Tài liệu quản lý (${data.documents.length}${data.docsHasMore ? '+' : ''})`
                      : 'Tài liệu quản lý'}
                  </span>
                </TabsTrigger>
              )}
              {canViewRequests && (
                <TabsTrigger
                  value="requests"
                  className="shrink-0 flex items-center gap-1.5 text-xs"
                >
                  <Clock size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.requests
                      ? `Yêu cầu cần duyệt (${pendingCount})`
                      : 'Yêu cầu cần duyệt'}
                  </span>
                </TabsTrigger>
              )}
              {canViewGrants && (
                <TabsTrigger value="grants" className="shrink-0 flex items-center gap-1.5 text-xs">
                  <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.grants
                      ? `Quyền truy cập (${activeGrantCount})`
                      : 'Quyền truy cập'}
                  </span>
                </TabsTrigger>
              )}
              {canViewHistory && (
                <TabsTrigger value="history" className="shrink-0 flex items-center gap-1.5 text-xs">
                  <History size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Lịch sử truy cập</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canViewDocsTab && (
              <TabsContent value="documents" className="space-y-4">
                <DocumentsTab
                  documents={filteredDocs}
                  docsPage={data.docsPage}
                  docsHasMore={data.docsHasMore}
                  isLoadingDocs={data.isLoadingDocs}
                  onLoadDocsPage={(page) => void data.loadDocumentsPage(page)}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  isLoadingPreview={delivery.isLoadingPreview}
                  openingDocId={delivery.openingDocId}
                  activatingDocIds={lifecycle.activatingDocIds}
                  downloadingDocIds={delivery.downloadingDocIds}
                  downloadingDocId={delivery.downloadingDocId}
                  sessionPosture={posture}
                  mfaActionHref={mfaActionHref}
                  canUpload={canUpload}
                  canManage={canManageDoc}
                  canView={canViewDoc}
                  canDownload={canDownloadDoc}
                  canCreateVersion={canCreateVersion}
                  canClassify={canClassifyDoc}
                  canArchive={canArchiveDoc}
                  onActivate={(doc) => lifecycle.handleActivateDocument(doc)}
                  onOpenPreview={(doc) => delivery.handleOpenPreview(doc)}
                  onDownload={(doc) => delivery.handleDownloadWithTicket(doc)}
                  onOpenEditMetadata={lifecycle.openEditMetadataModal}
                  onOpenTransferOwner={lifecycle.openTransferOwnerModal}
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
                  requestsPage={data.requestsPage}
                  requestsTotal={data.requestsTotal}
                  requestsTotalPages={data.requestsTotalPages}
                  isLoadingRequests={data.isLoadingRequests}
                  onLoadPage={(page) => void data.loadRequestsPage(page)}
                  canDecideRequest={canDecideRequest}
                  onOpenApprove={requestsControl.openApproveModal}
                  onOpenReject={requestsControl.openRejectModal}
                  onClearError={clearPageError}
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
                    data.setDialogError(null);
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
          departments={uploadWizard.permittedDepartments}
          businessCategories={data.businessCategories}
          classificationLevels={data.classificationLevels}
          userClearanceRank={user?.clearanceRank}
          userClearanceCode={user?.clearanceCode}
        />
        <DocumentLifecycleModals
          lifecycle={lifecycle}
          history={history}
          departments={uploadWizard.permittedDepartments}
          eligibleTransferUsers={grantsControl.eligibleUsers}
          canSetCurrentVersion={hasPermission('DOCUMENT_VERSION:CREATE')}
          classificationLevels={data.classificationLevels}
          businessCategories={data.businessCategories}
          userClearanceRank={user?.clearanceRank}
        />
        <AccessAndAuditModals
          grantsControl={grantsControl}
          requestsControl={requestsControl}
          delivery={delivery}
          rolesLookup={data.rolesLookup}
          auditDetailOpen={data.auditDetailOpen}
          onAuditDetailOpenChange={(open) => {
            if (!open) data.setDialogError(null);
            data.setAuditDetailOpen(open);
          }}
          selectedAuditLog={data.selectedAuditLog}
        />
      </div>
    </DialogErrorProvider>
  );
}
