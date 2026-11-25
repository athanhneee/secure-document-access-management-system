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
import type { AdminTab, UserRow } from './types';
import { DEFAULT_USER_LIST_QUERY, type UserListQueryState } from './users-query';

/**
 * Thuật toán: Không Gian Quản Trị Hệ Thống Đa Phân Hệ Cô Lập Sau `AuthGuard` & Lọc Tab Theo Quyền (`AdminWorkspace`)
 * Mục đích:
 *   - Đảm bảo `useAdminData()` chỉ khởi chạy sau khi `AuthGuard` xác nhận vai trò `SYSTEM_ADMIN`, ngăn triệt để các lời gọi API trái phép gây lỗi `403`.
 *   - Lọc hiển thị từng thẻ phân hệ và nút thao tác theo đúng quyền hạt mịn (`USER:MANAGE`, `DEPARTMENT:MANAGE`, `ROLE:MANAGE`, `POLICY:MANAGE`, `WATERMARK_CONFIG:MANAGE`, `SYSTEM_HEALTH:VIEW`/`MANAGE`).
 */
export function AdminWorkspace() {
  return (
    <AuthGuard requiredPortal="SYSTEM_ADMIN">
      <AppLayout>
        <AdminWorkspaceContent />
      </AppLayout>
    </AuthGuard>
  );
}

function AdminWorkspaceContent() {
  const { user, hasPermission } = useAuth();
  const canManageUsers = hasPermission('USER:MANAGE');
  const canManageDepartments = hasPermission('DEPARTMENT:MANAGE');
  const canManageRoles = hasPermission('ROLE:MANAGE');
  const canManagePolicies = hasPermission('POLICY:MANAGE');
  const canManageAttributes = hasPermission('ATTRIBUTE:MANAGE');
  const canSimulatePolicy = hasPermission('POLICY:SIMULATE');
  const canManageAbac = canManagePolicies || canManageAttributes || canSimulatePolicy;
  const canManageWatermark = hasPermission('WATERMARK_CONFIG:MANAGE');
  const canManageHealth = hasPermission('SYSTEM_HEALTH:MANAGE');
  const canViewHealth = hasPermission('SYSTEM_HEALTH:VIEW') || canManageHealth;

  const permittedTabs: AdminTab[] = [
    canManageUsers ? ('users' as const) : null,
    canManageDepartments ? ('departments' as const) : null,
    canManageRoles ? ('rbac' as const) : null,
    canManageAbac ? ('abac' as const) : null,
    canManageWatermark ? ('watermark' as const) : null,
    canViewHealth ? ('health' as const) : null,
  ].filter((t): t is AdminTab => t !== null);

  const [selectedTab, setSelectedTab] = useState<AdminTab>('users');
  const activeTab: AdminTab = permittedTabs.includes(selectedTab)
    ? selectedTab
    : (permittedTabs[0] ?? 'users');
  const [userQuery, setUserQuery] = useState<UserListQueryState>(DEFAULT_USER_LIST_QUERY);

  const data = useAdminData(activeTab, {
    canManageDepartments,
    canManageRoles,
    canManagePolicies,
    canManageAttributes,
    canSimulatePolicy,
  });
  const clearError = () => data.setErrorMessage(null);
  const modals = useAdminModalState(clearError);

  function handleOpenCreateUser() {
    void data.ensureTabLoaded('users');
    modals.openCreateUser();
  }

  function handleOpenAssignRole(targetUser: UserRow) {
    void data.ensureTabLoaded('rbac');
    modals.openAssignRole(targetUser);
  }

  async function handleModalSuccess(msg: string, targetTab?: AdminTab) {
    data.setErrorMessage(null);
    data.setMessage(msg);
    const tabToRefresh = targetTab ?? activeTab;
    await data.refresh({ silent: true, tab: tabToRefresh });
    if (tabToRefresh !== activeTab && data.loadedTabs[activeTab]) {
      await data.refresh({ silent: true, tab: activeTab });
    }
  }

  return (
    <DialogErrorProvider
      errorMessage={data.errorMessage}
      onDismiss={() => data.setErrorMessage(null)}
    >
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <Badge variant="success">Quản trị viên hệ thống</Badge>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
              Quản trị hệ thống
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
              onClick={() => void data.refresh()}
              disabled={data.isLoading}
            />
            {canManageUsers && (
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Tạo tài khoản"
                icon={<UserPlus size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={handleOpenCreateUser}
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
            onValueChange={(value) => setSelectedTab(value as AdminTab)}
            className="space-y-3.5"
          >
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 xl:inline-flex xl:w-auto h-auto min-h-10 rounded-[18px] xl:rounded-full p-1 gap-1 bg-[#f7f7f7] border border-[#ebebeb] text-[#717171]">
              {canManageUsers && (
                <TabsTrigger value="users" className="flex items-center gap-1.5 text-xs">
                  <Users size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.users ? `Tài khoản (${data.users.length})` : 'Tài khoản'}
                  </span>
                </TabsTrigger>
              )}
              {canManageDepartments && (
                <TabsTrigger value="departments" className="flex items-center gap-1.5 text-xs">
                  <Building2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {data.loadedTabs.departments
                      ? `Phòng ban (${data.departments.length})`
                      : 'Phòng ban'}
                  </span>
                </TabsTrigger>
              )}
              {canManageRoles && (
                <TabsTrigger value="rbac" className="flex items-center gap-1.5 text-xs">
                  <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>{data.loadedTabs.rbac ? `Vai trò (${data.roles.length})` : 'Vai trò'}</span>
                </TabsTrigger>
              )}
              {canManageAbac && (
                <TabsTrigger value="abac" className="flex items-center gap-1.5 text-xs">
                  <Scale size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Chính sách truy cập</span>
                </TabsTrigger>
              )}
              {canManageWatermark && (
                <TabsTrigger value="watermark" className="flex items-center gap-1.5 text-xs">
                  <Stamp size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Watermark bảo mật</span>
                </TabsTrigger>
              )}
              {canViewHealth && (
                <TabsTrigger value="health" className="flex items-center gap-1.5 text-xs">
                  <Activity size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Tình trạng hệ thống</span>
                </TabsTrigger>
              )}
            </TabsList>

            {canManageUsers && (
              <TabsContent value="users" className="space-y-4">
                <UsersTab
                  users={data.users}
                  departments={data.departments}
                  currentUserId={user?.id}
                  query={userQuery}
                  onQueryChange={setUserQuery}
                  onOpenEditUser={modals.openEditUser}
                  onOpenUpdateClearance={modals.openUpdateClearance}
                  onOpenAssignRole={handleOpenAssignRole}
                  onChangeStatus={data.changeUserStatus}
                  onClearError={clearError}
                />
              </TabsContent>
            )}

            {canManageDepartments && (
              <TabsContent value="departments" className="space-y-4">
                <DepartmentsTab
                  departments={data.departments}
                  onOpenCreateDepartment={modals.openCreateDepartment}
                  onOpenEditDepartment={modals.openEditDepartment}
                  onDeactivateDepartment={data.deactivateDepartment}
                  onActivateDepartment={data.activateDepartment}
                  onClearError={clearError}
                />
              </TabsContent>
            )}

            {canManageRoles && (
              <TabsContent value="rbac" className="space-y-4">
                <RolesTab
                  roles={data.roles}
                  currentUserRoles={user?.roles}
                  onOpenCreateRole={modals.openCreateRole}
                  onOpenRolePermissions={modals.openRolePermissions}
                  onOpenEditRole={modals.openEditRole}
                  onDisableRole={data.disableRole}
                  onEnableRole={data.enableRole}
                  onDeleteRole={data.deleteRole}
                  onClearError={clearError}
                />
              </TabsContent>
            )}

            {canManageAbac && (
              <TabsContent value="abac" className="space-y-4">
                <AbacTab
                  policies={data.policies}
                  attributes={data.attributes}
                  departments={data.abacDepartments}
                  businessCategories={data.businessCategories}
                  canManagePolicies={canManagePolicies}
                  canManageAttributes={canManageAttributes}
                  canSimulatePolicy={canSimulatePolicy}
                  onActivatePolicy={data.activatePolicy}
                  onDeactivatePolicy={data.deactivatePolicy}
                  onDeletePolicy={data.deletePolicy}
                  onSaveDraftPolicy={data.saveDraftPolicy}
                  onClearError={clearError}
                />
              </TabsContent>
            )}

            {canManageWatermark && (
              <TabsContent value="watermark" className="space-y-4">
                <WatermarkTab
                  configs={data.watermark.configs}
                  activeConfigId={data.watermark.activeConfigId}
                  showQr={data.watermark.showQr}
                  opacity={data.watermark.opacity}
                  fontSize={data.watermark.fontSize}
                  colorHex={data.watermark.colorHex}
                  rotationDegrees={data.watermark.rotationDegrees}
                  templateText={data.watermark.templateText}
                  previewUsername={user?.username}
                  previewFullName={user?.fullName}
                  isSaving={data.watermark.isSaving}
                  onSelectConfig={data.watermark.selectConfig}
                  onShowQrChange={data.watermark.setShowQr}
                  onOpacityChange={data.watermark.setOpacity}
                  onFontSizeChange={data.watermark.setFontSize}
                  onColorHexChange={data.watermark.setColorHex}
                  onRotationDegreesChange={data.watermark.setRotationDegrees}
                  onTemplateTextChange={data.watermark.setTemplateText}
                  onSaveConfig={() => void data.watermark.saveConfig()}
                />
              </TabsContent>
            )}

            {canViewHealth && (
              <TabsContent value="health" className="space-y-4">
                <SystemHealthTab
                  healthData={data.healthData}
                  onCaptureSnapshot={data.captureHealthSnapshot}
                  canManageHealth={canManageHealth}
                />
              </TabsContent>
            )}
          </Tabs>
        )}

        <AdminModals
          modals={modals}
          currentUserId={user?.id}
          departments={data.departments}
          clearanceOptions={data.clearanceOptions}
          roles={data.roles}
          permissions={data.permissions}
          onClearError={() => data.setErrorMessage(null)}
          onSuccess={handleModalSuccess}
          onError={data.setErrorMessage}
        />
      </div>
    </DialogErrorProvider>
  );
}
