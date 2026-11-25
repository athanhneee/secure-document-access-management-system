'use client';

import { useState } from 'react';
import { BookOpen, FileSearch, Clock, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { filterDiscoverableDocs } from './helpers';
import { useReaderCatalog } from './hooks/use-reader-catalog';
import { useReaderViewer } from './hooks/use-reader-viewer';
import { DocumentViewerModal } from './modals/document-viewer-modal';
import { RequestAccessModal } from './modals/request-access-modal';
import { CatalogTab } from './tabs/catalog-tab';
import { GrantedDocumentsTab } from './tabs/granted-documents-tab';
import { MyRequestsTab } from './tabs/my-requests-tab';

/**
 * Thuật toán: Không Gian Người Đọc Cô Lập Sau `AuthGuard` & Lọc Thao Tác Theo Quyền (`ReaderWorkspace`)
 * Mục đích:
 *   - Đảm bảo `useReaderCatalog()` không gọi API trước khi `AuthGuard` xác nhận vai trò `DOCUMENT_READER`.
 *   - Ẩn triệt để các nút tải bản sao / gửi yêu cầu / hủy yêu cầu hoặc các thẻ tab không nằm trong tập quyền hiệu lực.
 */
export function ReaderWorkspace() {
  return (
    <AuthGuard requiredRole="DOCUMENT_READER">
      <AppLayout>
        <ReaderWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function ReaderWorkspaceContent() {
  const { user, hasPermission } = useAuth();
  const canDiscover = hasPermission('DOCUMENT:DISCOVER');
  const canViewDocument = hasPermission('DOCUMENT:VIEW');
  const canDownloadDocument = hasPermission('DOCUMENT:DOWNLOAD');
  const canRequestAccess = hasPermission('ACCESS_REQUEST:CREATE');
  const canCancelRequest = hasPermission('ACCESS_REQUEST:CANCEL');
  const canViewRequests = hasPermission('ACCESS_REQUEST:VIEW_OWN') || canRequestAccess;

  const permittedTabs = [
    canDiscover ? 'discover' : null,
    canViewDocument ? 'my-docs' : null,
    canViewRequests ? 'my-requests' : null,
  ].filter((t): t is string => t !== null);

  const [selectedTab, setSelectedTab] = useState('discover');
  const activeTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'discover');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');

  const catalog = useReaderCatalog();
  const viewer = useReaderViewer({
    setMessage: catalog.setMessage,
    setErrorMessage: catalog.setErrorMessage,
  });

  const filteredDiscover = filterDiscoverableDocs(
    catalog.discoverDocs,
    searchQuery,
    selectedClassification,
  );

  return (
    <DialogErrorProvider
      errorMessage={catalog.errorMessage}
      onDismiss={() => catalog.setErrorMessage(null)}
    >
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <Badge variant="info">Người đọc tài liệu</Badge>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
              Tra cứu và đọc tài liệu mật
            </h1>
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
            onClick={() => void catalog.refreshData()}
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
            <AlertDescription className="ml-2">{catalog.message}</AlertDescription>
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
            <AlertDescription className="ml-2">{catalog.errorMessage}</AlertDescription>
          </Alert>
        )}

        {permittedTabs.length > 0 && (
          <Tabs value={activeTab} onValueChange={setSelectedTab} className="space-y-3.5">
            <TabsList className="grid w-full grid-cols-3 sm:inline-flex sm:w-auto h-auto min-h-10 rounded-[18px] sm:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canDiscover && (
                <TabsTrigger
                  value="discover"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
                >
                  <FileSearch
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Tra cứu tài liệu</span>
                  <span className="sm:hidden">Tra cứu</span>
                  <span className="text-xs opacity-80">({catalog.discoverDocs.length})</span>
                </TabsTrigger>
              )}
              {canViewDocument && (
                <TabsTrigger
                  value="my-docs"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
                >
                  <BookOpen size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                  <span className="hidden sm:inline">Tài liệu được cấp quyền</span>
                  <span className="sm:hidden">Được cấp</span>
                  <span className="text-xs opacity-80">({catalog.myDocs.length})</span>
                </TabsTrigger>
              )}
              {canViewRequests && (
                <TabsTrigger
                  value="my-requests"
                  className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
                >
                  <Clock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                  <span className="hidden sm:inline">Yêu cầu của tôi</span>
                  <span className="sm:hidden">Yêu cầu</span>
                  <span className="text-xs opacity-80">({catalog.myRequests.length})</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canDiscover && (
              <TabsContent value="discover" className="space-y-4">
                <CatalogTab
                  documents={filteredDiscover}
                  myDocs={catalog.myDocs}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  selectedClassification={selectedClassification}
                  onClassificationChange={setSelectedClassification}
                  canViewDocument={canViewDocument}
                  canRequestAccess={canRequestAccess}
                  onOpenPreview={(doc) => void viewer.handleOpenPreview(doc)}
                  onOpenRequestModal={catalog.openRequestModal}
                />
              </TabsContent>
            )}

            {canViewDocument && (
              <TabsContent value="my-docs" className="space-y-4">
                <GrantedDocumentsTab
                  myDocs={catalog.myDocs}
                  downloadingDocId={viewer.downloadingDocId}
                  canViewDocument={canViewDocument}
                  canDownloadDocument={canDownloadDocument}
                  onOpenPreview={(doc) => void viewer.handleOpenPreview(doc)}
                  onDownload={(doc) => void viewer.handleDownloadWithTicket(doc)}
                />
              </TabsContent>
            )}

            {canViewRequests && (
              <TabsContent value="my-requests" className="space-y-4">
                <MyRequestsTab
                  myRequests={catalog.myRequests}
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
        <DocumentViewerModal
          viewer={viewer}
          userFullName={user?.fullName}
          username={user?.username}
        />
        <ConfirmDialog
          open={catalog.pendingCancelRequestId !== null}
          onOpenChange={(open) => {
            if (!open) catalog.setPendingCancelRequestId(null);
          }}
          title="Xác nhận hủy yêu cầu truy cập"
          description="Bạn có chắc chắn muốn hủy yêu cầu quyền truy cập đang chờ phê duyệt này không?"
          confirmText="Hủy yêu cầu"
          cancelText="Giữ nguyên"
          variant="danger"
          isLoading={catalog.cancellingRequestId !== null}
          onConfirm={() => void catalog.handleCancelRequest()}
        />
      </div>
    </DialogErrorProvider>
  );
}
