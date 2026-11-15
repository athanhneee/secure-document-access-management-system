'use client';

import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Building2,
  CheckCircle2,
  RefreshCw,
  Scale,
  ShieldAlert,
  Stamp,
  UserPlus,
  Users,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { AuthGuard } from '@/components/auth-guard';
import { AppLayout } from '@/components/navigation/app-layout';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { DialogErrorProvider } from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAdminData } from './hooks/use-admin-data';
import { AdminModals, useAdminModalState } from './modals/admin-modals';
import { AbacTab } from './tabs/abac-tab';
import { DepartmentsTab } from './tabs/departments-tab';
import { RolesTab } from './tabs/roles-tab';
import { SystemHealthTab } from './tabs/system-health-tab';
import { UsersTab } from './tabs/users-tab';
import { WatermarkTab } from './tabs/watermark-tab';

/**
 * Thuật toán: Không gian Quản trị Hệ thống Đa Phân hệ Có Kiểm soát Quyền RBAC (`AdminWorkspace`)
 */
export function AdminWorkspace() {
  const [activeTab, setActiveTab] = useState('users');
  const [searchQuery, setSearchQuery] = useState('');
  const data = useAdminData();
  const clearError = () => data.setErrorMessage(null);
  const modals = useAdminModalState(clearError);

  const { isAuthenticated, user, hasRole } = useAuth();
  const canManage =
    isAuthenticated && (hasRole('SYSTEM_ADMIN') || user?.permissions.includes('USER:MANAGE'));

  async function handleModalSuccess(msg: string) {
    data.setErrorMessage(null);
    data.setMessage(msg);
    await data.refresh({ silent: true });
  }

  return (
    <AuthGuard requiredRole="SYSTEM_ADMIN">
      <AppLayout>
        <DialogErrorProvider
          errorMessage={data.errorMessage}
          onDismiss={() => data.setErrorMessage(null)}
        >
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div className="min-w-0">
                <Badge variant="success">System Admin</Badge>
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
                  Users · RBAC · ABAC · Watermark
                </h1>
              </div>

              {canManage && (
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
                    onClick={() => void data.refresh()}
                    disabled={data.isLoading}
                  />
                  <InteractiveHoverButton
                    variant="primary"
                    size="sm"
                    text="Tạo tài khoản"
                    icon={<UserPlus size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={modals.openCreateUser}
                  />
                </div>
              )}
            </div>

            {!canManage && (
              <div className="rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-6 text-center space-y-3">
                <p className="text-xs text-[#717171]">
                  Dữ liệu được quyết định và lọc theo quyền phía máy chủ. Bạn cần đăng nhập với
                  quyền Quản trị viên để thực hiện thao tác.
                </p>
              </div>
            )}

            {canManage && (
              <>
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

                <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-3.5">
                  <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 xl:inline-flex xl:w-auto h-auto min-h-10 rounded-[18px] xl:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
                    <TabsTrigger value="users" className="flex items-center gap-1.5 text-xs">
                      <Users size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>Tài khoản ({data.users.length})</span>
                    </TabsTrigger>
                    <TabsTrigger value="departments" className="flex items-center gap-1.5 text-xs">
                      <Building2 size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>Phòng ban ({data.departments.length})</span>
                    </TabsTrigger>
                    <TabsTrigger value="rbac" className="flex items-center gap-1.5 text-xs">
                      <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>Vai trò RBAC ({data.roles.length})</span>
                    </TabsTrigger>
                    <TabsTrigger value="abac" className="flex items-center gap-1.5 text-xs">
                      <Scale size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>Chính sách ABAC</span>
                    </TabsTrigger>
                    <TabsTrigger value="watermark" className="flex items-center gap-1.5 text-xs">
                      <Stamp size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>Cấu hình Watermark</span>
                    </TabsTrigger>
                    <TabsTrigger value="health" className="flex items-center gap-1.5 text-xs">
                      <Activity size={16} strokeWidth={1.75} aria-hidden="true" />
                      <span>System Health</span>
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="users" className="space-y-4">
                    <UsersTab
                      users={data.users}
                      departments={data.departments}
                      searchQuery={searchQuery}
                      onSearchQueryChange={setSearchQuery}
                      onOpenEditUser={modals.openEditUser}
                      onOpenAssignRole={modals.openAssignRole}
                      onChangeStatus={data.changeUserStatus}
                      onClearError={clearError}
                    />
                  </TabsContent>

                  <TabsContent value="departments" className="space-y-4">
                    <DepartmentsTab
                      departments={data.departments}
                      onOpenCreateDepartment={modals.openCreateDepartment}
                      onOpenEditDepartment={modals.openEditDepartment}
                    />
                  </TabsContent>

                  <TabsContent value="rbac" className="space-y-4">
                    <RolesTab
                      roles={data.roles}
                      onOpenCreateRole={modals.openCreateRole}
                      onOpenRolePermissions={modals.openRolePermissions}
                      onOpenEditRole={modals.openEditRole}
                      onDisableRole={data.disableRole}
                      onClearError={clearError}
                    />
                  </TabsContent>

                  <TabsContent value="abac" className="space-y-4">
                    <AbacTab
                      policies={data.policies}
                      attributes={data.attributes}
                      onActivatePolicy={data.activatePolicy}
                      onSaveDraftPolicy={data.saveDraftPolicy}
                      onClearError={clearError}
                    />
                  </TabsContent>

                  <TabsContent value="watermark" className="space-y-4">
                    <WatermarkTab
                      configs={data.watermark.configs}
                      activeConfigId={data.watermark.activeConfigId}
                      showQr={data.watermark.showQr}
                      opacity={data.watermark.opacity}
                      fontSize={data.watermark.fontSize}
                      templateText={data.watermark.templateText}
                      previewUsername={user?.username}
                      isSaving={data.watermark.isSaving}
                      onSelectConfig={data.watermark.selectConfig}
                      onShowQrChange={data.watermark.setShowQr}
                      onOpacityChange={data.watermark.setOpacity}
                      onFontSizeChange={data.watermark.setFontSize}
                      onTemplateTextChange={data.watermark.setTemplateText}
                      onSaveConfig={() => void data.watermark.saveConfig()}
                    />
                  </TabsContent>

                  <TabsContent value="health" className="space-y-4">
                    <SystemHealthTab
                      healthData={data.healthData}
                      onCaptureSnapshot={data.captureHealthSnapshot}
                    />
                  </TabsContent>
                </Tabs>

                <AdminModals
                  modals={modals}
                  departments={data.departments}
                  roles={data.roles}
                  permissions={data.permissions}
                  onClearError={() => data.setErrorMessage(null)}
                  onSuccess={handleModalSuccess}
                  onError={data.setErrorMessage}
                />
              </>
            )}
          </div>
        </DialogErrorProvider>
      </AppLayout>
    </AuthGuard>
  );
}
