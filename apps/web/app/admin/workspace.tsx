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
 * Mục đích: Điều phối tập trung quản lý người dùng, phòng ban, ma trận vai trò RBAC, chính sách ABAC, cấu hình thủy vân và giám sát sức khỏe hệ thống.
 * Cơ chế hoạt động:
 *   - Bảo vệ hai lớp bằng `AuthGuard` (`SYSTEM_ADMIN`) và cổng kiểm tra năng lực thực thi `canManage` (`SYSTEM_ADMIN` hoặc `USER:MANAGE`).
 */
export function AdminWorkspace() {
  const [activeTab, setActiveTab] = useState('users');
  const [searchQuery, setSearchQuery] = useState('');
  const modals = useAdminModalState();

  const {
    users,
    departments,
    roles,
    permissions,
    policies,
    attributes,
    healthData,
    watermark,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    refresh,
    changeUserStatus,
    disableRole,
    activatePolicy,
    saveDraftPolicy,
  } = useAdminData();

  const { isAuthenticated, user, hasRole } = useAuth();
  const canManage =
    isAuthenticated && (hasRole('SYSTEM_ADMIN') || user?.permissions.includes('USER:MANAGE'));

  async function handleModalSuccess(msg: string) {
    setMessage(msg);
    await refresh();
  }

  return (
    <AuthGuard requiredRole="SYSTEM_ADMIN">
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="success">System Admin</Badge>
                <span className="text-xs text-[#717171]">Phân hệ Quản trị</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222] mt-1">
                Users · RBAC · ABAC · Watermark
              </h1>
              <p className="text-xs text-[#717171]">
                Quản lý người dùng, cơ cấu phòng ban, ma trận phân quyền RBAC/ABAC toàn diện, cấu
                hình watermark và sức khỏe hệ thống
              </p>
            </div>

            {canManage && (
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
                  onClick={() => void refresh()}
                  disabled={isLoading}
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
                Dữ liệu được quyết định và lọc theo quyền phía máy chủ. Bạn cần đăng nhập với quyền
                Quản trị viên để thực hiện thao tác.
              </p>
            </div>
          )}

          {canManage && (
            <>
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
                <TabsList className="grid w-full grid-cols-2 md:grid-cols-6 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
                  <TabsTrigger value="users" className="flex items-center gap-1.5 text-xs">
                    <Users size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Tài khoản ({users.length})</span>
                  </TabsTrigger>
                  <TabsTrigger value="departments" className="flex items-center gap-1.5 text-xs">
                    <Building2 size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Phòng ban ({departments.length})</span>
                  </TabsTrigger>
                  <TabsTrigger value="rbac" className="flex items-center gap-1.5 text-xs">
                    <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Vai trò RBAC ({roles.length})</span>
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
                    users={users}
                    departments={departments}
                    searchQuery={searchQuery}
                    onSearchQueryChange={setSearchQuery}
                    onOpenAssignRole={modals.openAssignRole}
                    onChangeStatus={(u, action) => void changeUserStatus(u, action)}
                  />
                </TabsContent>

                <TabsContent value="departments" className="space-y-4">
                  <DepartmentsTab departments={departments} />
                </TabsContent>

                <TabsContent value="rbac" className="space-y-4">
                  <RolesTab
                    roles={roles}
                    onOpenCreateRole={modals.openCreateRole}
                    onOpenRolePermissions={modals.openRolePermissions}
                    onOpenEditRole={modals.openEditRole}
                    onDisableRole={(role) => void disableRole(role)}
                  />
                </TabsContent>

                <TabsContent value="abac" className="space-y-4">
                  <AbacTab
                    policies={policies}
                    attributes={attributes}
                    onActivatePolicy={(id) => void activatePolicy(id)}
                    onSaveDraftPolicy={saveDraftPolicy}
                  />
                </TabsContent>

                <TabsContent value="watermark" className="space-y-4">
                  <WatermarkTab
                    configs={watermark.configs}
                    activeConfigId={watermark.activeConfigId}
                    showQr={watermark.showQr}
                    opacity={watermark.opacity}
                    fontSize={watermark.fontSize}
                    isSaving={watermark.isSaving}
                    onSelectConfig={watermark.selectConfig}
                    onShowQrChange={watermark.setShowQr}
                    onOpacityChange={watermark.setOpacity}
                    onFontSizeChange={watermark.setFontSize}
                    onSaveConfig={() => void watermark.saveConfig()}
                  />
                </TabsContent>

                <TabsContent value="health" className="space-y-4">
                  <SystemHealthTab healthData={healthData} />
                </TabsContent>
              </Tabs>

              <AdminModals
                modals={modals}
                departments={departments}
                roles={roles}
                permissions={permissions}
                onClearError={() => setErrorMessage(null)}
                onSuccess={handleModalSuccess}
                onError={setErrorMessage}
              />
            </>
          )}
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
