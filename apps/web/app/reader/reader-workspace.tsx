'use client';

import { Suspense, useEffect, useState } from 'react';
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
import { AppLayout } from '@/components/navigation/app-layout';
import { WORKSPACE_TAB_EVENT } from '@/components/navigation/notification-bell-dialog';
import { AuthGuard } from '@/components/auth-guard';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent } from '@/components/ui/card';
import { useReaderCatalog } from './hooks/use-reader-catalog';
import { useReaderViewer } from './hooks/use-reader-viewer';
import { DocumentViewerModal } from './modals/document-viewer-modal';
import { RequestAccessModal } from './modals/request-access-modal';
import { CatalogTab } from './tabs/catalog-tab';
import { GrantedDocumentsTab } from './tabs/granted-documents-tab';
import { MyRequestsTab } from './tabs/my-requests-tab';

/**
 * Thuật toán: Không Gian Người Đọc Cô Lập Sau `AuthGuard`, Lọc Tab Theo Quyền Thực & Phản Hồi MFA (`ReaderWorkspace`)
 * Mục đích:
 *   - Đảm bảo `useReaderCatalog()` chỉ gọi API sau khi `AuthGuard` xác nhận quyền phân hệ `DOCUMENT_READER` và chỉ bật tab theo đúng quyền hạt mịn (`V-17`, `V-18`, `V-19`).
 *   - Hiển thị rõ cấp thẩm quyền bảo mật & phòng ban trực thuộc (`V-30`), hỗ trợ lối tắt kích hoạt/xác thực MFA ngay khi bị chặn `STEP_UP_MFA_REQUIRED` (`V-09`), lưới tab di động động (`V-60`) và triệt tiêu lỗi lặp đôi trong hộp thoại (`V-44`).
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

const VALID_READER_TABS = new Set(['discover', 'my-docs', 'my-requests']);

function ReaderWorkspaceContent() {
  const { user, hasPermission } = useAuth();
  const searchParams = useSearchParams();
  const canDiscover = hasPermission('DOCUMENT:DISCOVER');
  const canViewDocument = hasPermission('DOCUMENT:VIEW');
  const canDownloadDocument = hasPermission('DOCUMENT:DOWNLOAD');
  const canRequestAccess = hasPermission('ACCESS_REQUEST:CREATE');
  const canCancelRequest = hasPermission('ACCESS_REQUEST:CANCEL');
  // CONFLICT-RESOLVED: Chỉ hiển thị tab Yêu cầu của tôi khi tài khoản có quyền ACCESS_REQUEST:VIEW_OWN khớp yêu cầu API GET /access-requests?scope=my (V-19).
  const canViewRequests = hasPermission('ACCESS_REQUEST:VIEW_OWN');

  const permittedTabs = [
    canDiscover ? 'discover' : null,
    canViewDocument ? 'my-docs' : null,
    canViewRequests ? 'my-requests' : null,
  ].filter((t): t is string => t !== null);

  const requestedTabParam = searchParams.get('tab');
  const [selectedTab, setSelectedTab] = useState(() =>
    requestedTabParam && VALID_READER_TABS.has(requestedTabParam) ? requestedTabParam : 'discover',
  );

  // Đồng bộ tham số `?tab=` và sự kiện chuyển tab tức thì từ chuông thông báo nội bộ ngay cả khi đang ở sẵn `/reader` (`V-53`)
  useEffect(() => {
    if (requestedTabParam && VALID_READER_TABS.has(requestedTabParam)) {
      // oxlint-disable-next-line react/set-state-in-effect
      setSelectedTab(requestedTabParam);
    }
  }, [requestedTabParam]);

  useEffect(() => {
    function handleTabSync(event: Event) {
      const detail = (event as CustomEvent<{ path?: string; tab?: string }>).detail;
      if (detail?.path === '/reader' && detail.tab && VALID_READER_TABS.has(detail.tab)) {
        setSelectedTab(detail.tab);
      }
    }
    window.addEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
    return () => window.removeEventListener(WORKSPACE_TAB_EVENT, handleTabSync);
  }, []);

  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'discover');

  const catalog = useReaderCatalog();
  const viewer = useReaderViewer({
    setMessage: catalog.setMessage,
    setErrorMessage: catalog.setErrorMessage,
  });

  const isAnyModalOpen =
    catalog.requestModalOpen || viewer.previewOpen || catalog.pendingCancelRequestId !== null;
  const mobileTabGridClass =
    permittedTabs.length === 1
      ? 'grid-cols-1'
      : permittedTabs.length === 2
        ? 'grid-cols-2'
        : 'grid-cols-3';
  const mfaActionHref = user?.mfaEnabled
    ? '/mfa?redirect=%2Freader'
    : '/mfa?enroll=1&method=totp&redirect=%2Freader';

  return (
    <DialogErrorProvider
      errorMessage={catalog.errorMessage}
      onDismiss={() => {
        catalog.setErrorMessage(null);
        viewer.clearMfaActionRequired();
      }}
    >
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <Badge variant="info">Người đọc tài liệu</Badge>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222]">
              Tra cứu và đọc tài liệu mật
            </h1>
            {user && (
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#717171]">
                {user.clearanceCode && (
                  <ClassificationBadge
                    level={user.clearanceCode}
                    rank={user.clearanceRank}
                    subject="user"
                    showRank
                    size="sm"
                  />
                )}
                {user.departmentName && (
                  <span className="inline-flex items-center gap-1 text-[#222222] font-medium">
                    <Building2
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#717171] shrink-0"
                      aria-hidden="true"
                    />
                    <span>{user.departmentName}</span>
                  </span>
                )}
              </div>
            )}
          </div>

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
              return catalog.refreshData();
            }}
            disabled={catalog.isLoading}
            className="shrink-0 self-start sm:self-auto"
          />
        </div>

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
                className="shrink-0 flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#008A05] hover:bg-[#008A05]/10 cursor-pointer"
              >
                <X size={16} strokeWidth={2} aria-hidden="true" />
              </button>
            </div>
          </Alert>
        )}

        {catalog.errorMessage && !isAnyModalOpen && (
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
                  className="shrink-0 flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#C13515] hover:bg-[#C13515]/10 cursor-pointer"
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
                      {user?.mfaEnabled ? 'Xác thực MFA ngay' : 'Thiết lập MFA (TOTP / Passkey)'}
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
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-3.5">
            <TabsList
              className={`grid w-full ${mobileTabGridClass} sm:inline-flex sm:w-auto h-auto min-h-10 rounded-[18px] sm:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]`}
            >
              {canDiscover && (
                <TabsTrigger
                  value="discover"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1.5 sm:px-2.5"
                >
                  <FileSearch
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Tra cứu tài liệu</span>
                  <span className="sm:hidden">Tra cứu</span>
                  <span className="text-xs opacity-80">
                    ({catalog.discoverDocs.length}
                    {catalog.discoverHasMore ? '+' : ''})
                  </span>
                </TabsTrigger>
              )}
              {canViewDocument && (
                <TabsTrigger
                  value="my-docs"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1.5 sm:px-2.5"
                >
                  <BookOpen size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                  <span className="hidden sm:inline">Tài liệu được cấp quyền</span>
                  <span className="sm:hidden">Được cấp</span>
                  <span className="text-xs opacity-80">
                    ({catalog.myDocs.length}
                    {catalog.grantsHasMore ? '+' : ''})
                  </span>
                </TabsTrigger>
              )}
              {canViewRequests && (
                <TabsTrigger
                  value="my-requests"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1.5 sm:px-2.5"
                >
                  <Clock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                  <span className="hidden sm:inline">Yêu cầu của tôi</span>
                  <span className="sm:hidden">Yêu cầu</span>
                  <span className="text-xs opacity-80">({catalog.requestsTotal})</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canDiscover && (
              <TabsContent value="discover" className="space-y-4">
                <CatalogTab
                  documents={catalog.discoverDocs}
                  myDocs={catalog.myDocs}
                  myRequests={catalog.myRequests}
                  isLoading={catalog.isLoading}
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
                  isLoading={catalog.isLoading}
                  page={catalog.grantsPage}
                  hasMore={catalog.grantsHasMore}
                  onPageChange={catalog.setGrantsPage}
                  downloadingDocIds={viewer.downloadingDocIds}
                  canViewDocument={canViewDocument}
                  canDownloadDocument={canDownloadDocument}
                  canRequestAccess={canRequestAccess}
                  onOpenPreview={(doc) => viewer.handleOpenPreview(doc)}
                  onDownload={(doc) => viewer.handleDownloadWithTicket(doc)}
                  onRequestUpgrade={(doc, action) =>
                    catalog.openRequestModal(
                      {
                        id: doc.documentId,
                        title: doc.title,
                        documentCode: doc.documentCode,
                        classificationCode: doc.classificationCode,
                        classificationRank: 1,
                        allowDownload: doc.allowDownload,
                      },
                      action,
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
                  isLoading={catalog.isLoading}
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
            if (!open) catalog.setPendingCancelRequestId(null);
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
