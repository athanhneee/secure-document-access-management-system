'use client';

import { useState } from 'react';
import { BookOpen, FileSearch, Clock, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
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
 * Thuật toán: Không gian Khám phá Danh mục Không Rò rỉ & Đọc Tài liệu An toàn (`ReaderWorkspace`)
 * Mục đích: Cho phép người đọc tra cứu siêu dữ liệu danh mục được phép khám phá, gửi yêu cầu xin quyền và xem/tải tài liệu qua phiên PEP gắn thủy vân.
 * Cơ chế hoạt động:
 *   - Kết hợp lọc đa tiêu chí danh mục phía máy khách (`filterDiscoverableDocs`) với trình đọc PDF đóng hộp cát (`useReaderViewer`).
 */
export function ReaderWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('discover');
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
    <AuthGuard requiredRole="DOCUMENT_READER">
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="info">Document Reader</Badge>
                <span className="text-xs text-[#717171]">Phân hệ Người đọc</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Khám phá & Đọc Tài liệu Mật
              </h1>
              <p className="text-xs text-[#717171]">
                Tìm kiếm danh mục tài liệu, gửi yêu cầu cấp quyền, xem trước an toàn và tải bản sao
                có watermark
              </p>
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

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-3 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
              <TabsTrigger
                value="discover"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <FileSearch size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Khám phá danh mục</span>
                <span className="sm:hidden">Khám phá</span>
                <span className="text-[11px] opacity-80">({catalog.discoverDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger
                value="my-docs"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <BookOpen size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Tài liệu được xem</span>
                <span className="sm:hidden">Được xem</span>
                <span className="text-[11px] opacity-80">({catalog.myDocs.length})</span>
              </TabsTrigger>
              <TabsTrigger
                value="my-requests"
                className="flex items-center justify-center gap-1 sm:gap-1.5 text-xs py-1.5 px-1 sm:px-2"
              >
                <Clock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span className="hidden sm:inline">Theo dõi yêu cầu</span>
                <span className="sm:hidden">Yêu cầu</span>
                <span className="text-[11px] opacity-80">({catalog.myRequests.length})</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="discover" className="space-y-4">
              <CatalogTab
                documents={filteredDiscover}
                myDocs={catalog.myDocs}
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                selectedClassification={selectedClassification}
                onClassificationChange={setSelectedClassification}
                onOpenPreview={(doc) => void viewer.handleOpenPreview(doc)}
                onOpenRequestModal={catalog.openRequestModal}
              />
            </TabsContent>

            <TabsContent value="my-docs" className="space-y-4">
              <GrantedDocumentsTab
                myDocs={catalog.myDocs}
                downloadingDocId={viewer.downloadingDocId}
                onOpenPreview={(doc) => void viewer.handleOpenPreview(doc)}
                onDownload={(doc) => void viewer.handleDownloadWithTicket(doc)}
              />
            </TabsContent>

            <TabsContent value="my-requests" className="space-y-4">
              <MyRequestsTab
                myRequests={catalog.myRequests}
                cancellingRequestId={catalog.cancellingRequestId}
                onCancelRequest={(id) => catalog.setPendingCancelRequestId(id)}
              />
            </TabsContent>
          </Tabs>

          <RequestAccessModal catalog={catalog} />
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
            title="Xác nhận hủy yêu cầu cấp quyền"
            description="Bạn có chắc chắn muốn hủy yêu cầu cấp quyền đang chờ phê duyệt này không?"
            confirmText="Hủy yêu cầu"
            variant="danger"
            isLoading={catalog.cancellingRequestId !== null}
            onConfirm={() => void catalog.handleCancelRequest()}
          />
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
