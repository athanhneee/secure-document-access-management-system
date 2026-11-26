'use client';

import { Suspense, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  AlertTriangle,
  BookOpen,
  Building2,
  CheckCircle2,
  Clock,
  FileSearch,
  Lock,
  RefreshCw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { useSessionPosture } from '@/lib/use-session-posture';
import { useWorkspaceTabSync } from '@/lib/use-workspace-tab-sync';
import { AppLayout } from '@/components/navigation/app-layout';
import { WORKSPACE_TAB_EVENT } from '@/components/navigation/notification-bell-dialog';
import { AuthGuard } from '@/components/auth-guard';
import { ClassificationBadge } from '@/components/classification-badge';
import { SessionPostureBanner } from '@/components/documents/session-posture-banner';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent } from '@/components/ui/card';
import { rankFromCode } from './helpers';
import { useReaderCatalog } from './hooks/use-reader-catalog';
import { useReaderViewer } from './hooks/use-reader-viewer';
import { DocumentViewerModal } from './modals/document-viewer-modal';
import { RequestAccessModal } from './modals/request-access-modal';
import { CatalogTab } from './tabs/catalog-tab';
import { GrantedDocumentsTab } from './tabs/granted-documents-tab';
import { MyRequestsTab } from './tabs/my-requests-tab';

type ReaderTab = 'discover' | 'my-docs' | 'my-requests';

/**
 * Thuật toán: Không Gian Người Đọc Cô Lập Sau `AuthGuard`, Đồng Bộ URL `?tab=` & Tách Lỗi Hộp Thoại (`ReaderWorkspace`, BUG-090, BUG-102, BUG-103)
 * Mục đích:
 *   - Đảm bảo `useReaderCatalog()` chỉ gọi API sau khi `AuthGuard` xác nhận quyền phân hệ `DOCUMENT_READER` và đồng bộ hai chiều `?tab=` qua `useWorkspaceTabSync` (`BUG-090`).
 *   - Tách riêng `dialogError` của modal khỏi `errorMessage` trang nền (`BUG-102`) và truyền trạng thái tải riêng biệt theo từng tab (`BUG-103`).
 */
export function ReaderWorkspace() {
  return (
    <AuthGuard requiredPortal="DOCUMENT_READER">
      <AppLayout>
        <Suspense fallback={null}>
          <ReaderWorkspaceContent />
        </Suspense>
      </AppLayout>
    </AuthGuard>
  );
}

function ReaderWorkspaceContent() {
  const { user, hasPermission } = useAuth();
  const searchParams = useSearchParams();
  const canDiscover = hasPermission('DOCUMENT:DISCOVER');
  const canViewDocument = hasPermission('DOCUMENT:VIEW');
  const canDownloadDocument = hasPermission('DOCUMENT:DOWNLOAD');
  const canRequestAccess = hasPermission('ACCESS_REQUEST:CREATE');
  const canCancelRequest = hasPermission('ACCESS_REQUEST:CANCEL');
  const canViewRequests = hasPermission('ACCESS_REQUEST:VIEW_OWN');

  const permittedTabs = useMemo<readonly ReaderTab[]>(
    () =>
      [
        canDiscover ? 'discover' : null,
        canViewDocument ? 'my-docs' : null,
        canViewRequests ? 'my-requests' : null,
      ].filter((t): t is ReaderTab => t !== null),
    [canDiscover, canViewDocument, canViewRequests],
  );

  const [activeTab, setActiveTab] = useWorkspaceTabSync<ReaderTab>(permittedTabs, 'discover');

  useEffect(() => {
    function handleTabSync(event: Event) {
      const detail = (event as CustomEvent<{ path?: string; tab?: string }>).detail;
      if (
        detail?.path === '/reader' &&
        detail.tab &&
        permittedTabs.includes(detail.tab as ReaderTab)
      ) {
        setActiveTab(detail.tab as ReaderTab);
      }
    }
    window.addEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
    return () => window.removeEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
  }, [permittedTabs, setActiveTab]);

  const catalog = useReaderCatalog();
  const { posture, refreshPosture } = useSessionPosture(Boolean(user));
  const viewer = useReaderViewer({
    setMessage: catalog.setMessage,
    setErrorMessage: catalog.setErrorMessage,
  });

  const mobileTabGridClass =
    permittedTabs.length === 1
      ? 'grid-cols-1'
      : permittedTabs.length === 2
        ? 'grid-cols-2'
        : 'grid-cols-3';
  const effectiveMfaEnabled = posture?.mfaEnabled ?? user?.mfaEnabled;
  const currentTabQuery = searchParams.get('tab');
  const redirectTarget = encodeURIComponent(
    currentTabQuery ? `/reader?tab=${currentTabQuery}` : '/reader',
  );
  const mfaActionHref = effectiveMfaEnabled
    ? `/mfa?redirect=${redirectTarget}`
    : `/mfa?enroll=1&method=totp&redirect=${redirectTarget}`;
  const hasTopSecretDocs =
    catalog.myDocs.some((d) => d.classificationCode === 'TOP_SECRET') ||
    [...catalog.activeGrantsByDocId.values()].some((d) => d.classificationCode === 'TOP_SECRET') ||
    catalog.discoverDocs.some((d) => d.classificationCode === 'TOP_SECRET');

  return (
    <DialogErrorProvider
      errorMessage={catalog.dialogError}
      onDismiss={() => {
        catalog.setDialogError(null);
      }}
    >
      <div className="space-y-3.5 sm:space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <Badge variant="info" className="hidden sm:inline-flex">
              Người đọc tài liệu
            </Badge>
            <h1 className="text-lg sm:text-2xl font-bold tracking-tight text-[#222222] leading-snug">
              Tra cứu và đọc tài liệu mật
            </h1>
            {user && (user.clearanceCode || user.departmentName) && (
              <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-x-2 gap-y-1 text-xs text-[#717171]">
                {user.clearanceCode && (
                  <ClassificationBadge
                    level={user.clearanceCode}
                    rank={user.clearanceRank}
                    subject="user"
                    showRank
                    size="sm"
                  />
                )}
                {user.clearanceCode && user.departmentName && (
                  <span className="hidden sm:inline text-[#dddddd]" aria-hidden="true">
                    ·
                  </span>
                )}
                {user.departmentName && (
                  <span className="inline-flex min-w-0 items-center gap-1 text-[#717171] font-medium">
                    <Building2
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#717171] shrink-0"
                      aria-hidden="true"
                    />
                    <span className="truncate">{user.departmentName}</span>
                  </span>
                )}
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={() => {
              viewer.clearMfaActionRequired();
              void refreshPosture();
              void catalog.refreshData();
            }}
            disabled={catalog.isLoading}
            aria-label="Làm mới"
            title="Làm mới dữ liệu"
            className="flex sm:hidden h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
          >
            <RefreshCw
              size={16}
              strokeWidth={1.75}
              className={catalog.isLoading ? 'animate-spin' : ''}
              aria-hidden="true"
            />
          </button>

          <span className="hidden sm:inline-flex shrink-0">
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Làm mới"
              icon={
                <RefreshCw
                  size={16}
                  strokeWidth={1.75}
                  className={catalog.isLoading ? 'animate-spin' : ''}
                  aria-hidden="true"
                />
              }
              onClick={() => {
                viewer.clearMfaActionRequired();
                void refreshPosture();
                return catalog.refreshData();
              }}
              disabled={catalog.isLoading}
            />
          </span>
        </div>

        <SessionPostureBanner
          posture={posture}
          mfaActionHref={mfaActionHref}
          userClearanceRank={user?.clearanceRank}
          hasTopSecretDocuments={hasTopSecretDocs}
          suppressProactiveAlert={Boolean(catalog.errorMessage)}
        />

        {catalog.message && (
          <Alert variant="success" className="text-xs">
            <CheckCircle2
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#008A05]"
              aria-hidden="true"
            />
            <div className="ml-2 flex items-start justify-between gap-2 w-full">
              <AlertDescription>{catalog.message}</AlertDescription>
              <button
                type="button"
                onClick={() => catalog.setMessage(null)}
                aria-label="Đóng thông báo thành công"
                className="shrink-0 flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#008A05] hover:bg-[#f7f7f7] cursor-pointer"
              >
                <X size={16} strokeWidth={2} aria-hidden="true" />
              </button>
            </div>
          </Alert>
        )}

        {catalog.errorMessage && (
          <Alert variant="destructive" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <div className="ml-2 flex flex-col gap-2 w-full">
              <div className="flex items-start justify-between gap-2">
                <AlertDescription>{catalog.errorMessage}</AlertDescription>
                <button
                  type="button"
                  onClick={() => {
                    catalog.setErrorMessage(null);
                    viewer.clearMfaActionRequired();
                  }}
                  aria-label="Đóng thông báo lỗi"
                  className="shrink-0 flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#C13515] hover:bg-[#f7f7f7] cursor-pointer"
                >
                  <X size={16} strokeWidth={2} aria-hidden="true" />
                </button>
              </div>
              {viewer.mfaActionRequired && (
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

        {permittedTabs.length === 0 ? (
          <Card>
            <CardContent className="py-10 text-center space-y-2">
              <div className="flex justify-center text-[#717171]">
                <Lock size={24} strokeWidth={1.75} aria-hidden="true" />
              </div>
              <p className="text-sm font-semibold text-[#222222]">
                Chưa có tính năng Người đọc nào được kích hoạt
              </p>
              <p className="text-xs text-[#717171] max-w-md mx-auto leading-relaxed">
                Tài khoản của bạn hiện không sở hữu quyền tra cứu danh mục, xem tài liệu hay theo
                dõi yêu cầu. Vui lòng liên hệ quản trị viên để được cấp quyền phù hợp.
              </p>
            </CardContent>
          </Card>
        ) : (
          <Tabs
            value={activeTab}
            onValueChange={(next) => setActiveTab(next as ReaderTab)}
            className="space-y-3"
          >
            <TabsList
              className={`grid w-full ${mobileTabGridClass} sm:inline-flex sm:w-auto h-auto min-h-11 sm:min-h-10 rounded-[14px] sm:rounded-full p-1 gap-1 bg-[#ebebeb]/70 sm:bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]`}
            >
              {canDiscover && (
                <TabsTrigger
                  value="discover"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-2 sm:py-1.5 px-2 sm:px-3"
                >
                  <FileSearch
                    size={16}
                    strokeWidth={1.75}
                    className="hidden sm:inline-block shrink-0"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Tra cứu tài liệu</span>
                  <span className="sm:hidden">Tra cứu</span>
                  <span className="text-xs opacity-75 tabular-nums">
                    ({catalog.discoverDocs.length}
                    {catalog.discoverHasMore ? '+' : ''})
                  </span>
                </TabsTrigger>
              )}
              {canViewDocument && (
                <TabsTrigger
                  value="my-docs"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-2 sm:py-1.5 px-2 sm:px-3"
                >
                  <BookOpen
                    size={16}
                    strokeWidth={1.75}
                    className="hidden sm:inline-block shrink-0"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Tài liệu được cấp quyền</span>
                  <span className="sm:hidden">Được cấp</span>
                  <span className="text-xs opacity-75 tabular-nums">
                    ({catalog.myDocs.length}
                    {catalog.grantsHasMore ? '+' : ''})
                  </span>
                </TabsTrigger>
              )}
              {canViewRequests && (
                <TabsTrigger
                  value="my-requests"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-2 sm:py-1.5 px-2 sm:px-3"
                >
                  <Clock
                    size={16}
                    strokeWidth={1.75}
                    className="hidden sm:inline-block shrink-0"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Yêu cầu của tôi</span>
                  <span className="sm:hidden">Yêu cầu</span>
                  <span className="text-xs opacity-75 tabular-nums">({catalog.requestsTotal})</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canDiscover && (
              <TabsContent value="discover" className="space-y-4">
                <CatalogTab
                  documents={catalog.discoverDocs}
                  myDocs={catalog.myDocs}
                  activeGrantsByDocId={catalog.activeGrantsByDocId}
                  myRequests={catalog.myRequests}
                  pendingRequestDocIds={catalog.pendingRequestDocIds}
                  isLoading={catalog.isLoadingCatalog}
                  page={catalog.discoverPage}
                  hasMore={catalog.discoverHasMore}
                  onPageChange={catalog.setDiscoverPage}
                  userClearanceRank={user?.clearanceRank}
                  searchQuery={catalog.searchQuery}
                  onSearchChange={catalog.setSearchQuery}
                  selectedClassification={catalog.selectedClassification}
                  onClassificationChange={catalog.setSelectedClassification}
                  canViewDocument={canViewDocument}
                  canDownloadDocument={canDownloadDocument}
                  canRequestAccess={canRequestAccess}
                  openingDocId={viewer.openingDocId}
                  sessionPosture={posture}
                  mfaActionHref={mfaActionHref}
                  onOpenPreview={(doc) => viewer.handleOpenPreview(doc)}
                  onOpenRequestModal={catalog.openRequestModal}
                />
              </TabsContent>
            )}

            {canViewDocument && (
              <TabsContent value="my-docs" className="space-y-4">
                <GrantedDocumentsTab
                  myDocs={catalog.myDocs}
                  myRequests={catalog.myRequests}
                  pendingRequestDocIds={catalog.pendingRequestDocIds}
                  isLoading={catalog.isLoadingGrants}
                  page={catalog.grantsPage}
                  hasMore={catalog.grantsHasMore}
                  onPageChange={catalog.setGrantsPage}
                  openingDocId={viewer.openingDocId}
                  downloadingDocIds={viewer.downloadingDocIds}
                  sessionPosture={posture}
                  mfaActionHref={mfaActionHref}
                  canViewDocument={canViewDocument}
                  canDownloadDocument={canDownloadDocument}
                  canRequestAccess={canRequestAccess}
                  onOpenPreview={(doc) => viewer.handleOpenPreview(doc)}
                  onDownload={(doc) => viewer.handleDownloadWithTicket(doc)}
                  onRequestUpgrade={(doc, action, intent) =>
                    catalog.openRequestModal(
                      {
                        id: doc.documentId,
                        title: doc.title,
                        documentCode: doc.documentCode,
                        classificationCode: doc.classificationCode,
                        classificationRank: rankFromCode(doc.classificationCode),
                        allowDownload: doc.allowDownload,
                        retentionUntil: doc.retentionUntil,
                        defaultViewDays: doc.defaultViewDays,
                      },
                      action,
                      {
                        existingGrantValidUntil: doc.validUntil,
                        intent: intent ?? (action === 'DOWNLOAD' ? 'UPGRADE_DOWNLOAD' : 'RENEW'),
                      },
                    )
                  }
                />
              </TabsContent>
            )}

            {canViewRequests && (
              <TabsContent value="my-requests" className="space-y-4">
                <MyRequestsTab
                  myRequests={catalog.myRequests}
                  totalCount={catalog.requestsTotal}
                  isLoading={catalog.isLoadingRequests}
                  page={catalog.requestsPage}
                  hasMore={catalog.requestsHasMore}
                  onPageChange={catalog.setRequestsPage}
                  statusFilter={catalog.requestStatusFilter}
                  onStatusFilterChange={catalog.setRequestStatusFilter}
                  cancellingRequestId={catalog.cancellingRequestId}
                  canCancelRequest={canCancelRequest}
                  onCancelRequest={(id) => {
                    catalog.setErrorMessage(null);
                    catalog.setPendingCancelRequestId(id);
                  }}
                />
              </TabsContent>
            )}
          </Tabs>
        )}

        <RequestAccessModal catalog={catalog} canDownloadDocument={canDownloadDocument} />
        <DocumentViewerModal viewer={viewer} />
        <ConfirmDialog
          open={catalog.pendingCancelRequestId !== null}
          onOpenChange={(open) => {
            if (!open && !catalog.cancellingRequestId) {
              catalog.setPendingCancelRequestId(null);
            }
          }}
          title="Xác nhận hủy yêu cầu truy cập"
          description={
            catalog.pendingCancelRequest
              ? `Bạn có chắc chắn muốn hủy yêu cầu quyền truy cập đang chờ phê duyệt đối với tài liệu "${catalog.pendingCancelRequest.documentTitle}" không?`
              : 'Bạn có chắc chắn muốn hủy yêu cầu quyền truy cập đang chờ phê duyệt này không?'
          }
          confirmText="Hủy yêu cầu"
          cancelText="Giữ nguyên"
          variant="danger"
          isLoading={catalog.cancellingRequestId !== null}
          onConfirm={() => catalog.handleCancelRequest()}
        />
      </div>
    </DialogErrorProvider>
  );
}
