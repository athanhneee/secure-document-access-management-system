'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  Users,
  Building2,
  ShieldAlert,
  Scale,
  Stamp,
  Activity,
  UserPlus,
  Lock,
  Unlock,
  Ban,
  Search,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  QrCode,
  Check,
  Plus,
  Play,
  Settings2,
  Key,
  ShieldCheck,
  Edit2,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Button } from '@/components/ui/button';
import { VisualPolicyBuilder } from '@/components/abac/visual-policy-builder';
import { PolicySimulatorDialog } from '@/components/abac/policy-simulator-dialog';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { PRESET_POLICY_TEMPLATES } from '@/components/abac/policy-templates';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface UserRow {
  id: string;
  username: string;
  fullName: string;
  email: string;
  status: string;
  departmentId: string | null;
  version: number;
}

interface DepartmentRow {
  id: string;
  code: string;
  name: string;
  parentId: string | null;
  isActive: boolean;
  version: number;
}

interface RoleRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  isSystemRole: boolean;
  isActive: boolean;
  version: number;
  permissions: Array<{ id?: string; code: string; name?: string }>;
}

interface PermissionRow {
  id: string;
  code: string;
  resourceType: string;
  action: string;
  description?: string | null;
}

interface AbacPolicyRow {
  id: string;
  name: string;
  description: string;
  effect: 'PERMIT' | 'DENY';
  isActive: boolean;
}

interface AttributeOptionRow {
  id: string;
  code: string;
  name: string;
  numeric_rank?: number | null;
}

interface AttributeDefinitionRow {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  data_type?: string | null;
  attribute_options: AttributeOptionRow[];
}

interface WatermarkConfigRow {
  id: string;
  name: string;
  opacityPercent: number;
  rotationDegrees?: number;
  fontSize: number;
  colorHex?: string;
  includeQrCode: boolean;
  isDefault: boolean;
  isVisible: boolean;
  templateText?: string;
}

interface SystemHealthData {
  status: string;
  database: { status: string; latencyMs?: number | undefined };
  cache: { status: string };
  uptimeSeconds: number;
}

export function AdminWorkspace() {
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState<UserRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [abacSubTab, setAbacSubTab] = useState<'policies' | 'attributes'>('policies');
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Create User Modal state
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newDepartmentId, setNewDepartmentId] = useState('');

  // RBAC Modals state
  const [createRoleOpen, setCreateRoleOpen] = useState(false);
  const [newRoleCode, setNewRoleCode] = useState('');
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [isCreatingRole, setIsCreatingRole] = useState(false);

  const [editRoleOpen, setEditRoleOpen] = useState(false);
  const [selectedRoleForEdit, setSelectedRoleForEdit] = useState<RoleRow | null>(null);
  const [editRoleName, setEditRoleName] = useState('');
  const [editRoleDesc, setEditRoleDesc] = useState('');
  const [isEditingRole, setIsEditingRole] = useState(false);

  const [permsModalOpen, setPermsModalOpen] = useState(false);
  const [selectedRoleForPerms, setSelectedRoleForPerms] = useState<RoleRow | null>(null);
  const [selectedPermIds, setSelectedPermIds] = useState<string[]>([]);
  const [isSavingPerms, setIsSavingPerms] = useState(false);

  const [assignRoleOpen, setAssignRoleOpen] = useState(false);
  const [selectedUserForRole, setSelectedUserForRole] = useState<UserRow | null>(null);
  const [assignRoleId, setAssignRoleId] = useState('');
  const [assignValidFrom, setAssignValidFrom] = useState('');
  const [assignValidTo, setAssignValidTo] = useState('');
  const [isAssigningRole, setIsAssigningRole] = useState(false);

  // Watermark Server Config state
  const [watermarkConfigs, setWatermarkConfigs] = useState<WatermarkConfigRow[]>([]);
  const [activeWmConfigId, setActiveWmConfigId] = useState<string | null>(null);
  const [wmShowQr, setWmShowQr] = useState(true);
  const [wmOpacity, setWmOpacity] = useState(25);
  const [wmFontSize, setWmFontSize] = useState(14);
  const [isSavingWatermark, setIsSavingWatermark] = useState(false);

  // Visual Policy Builder & Simulator states
  const [builderOpen, setBuilderOpen] = useState(false);
  const [selectedRuleForBuilder, setSelectedRuleForBuilder] = useState<
    VisualPolicyRule | undefined
  >(undefined);
  const [simulatorOpen, setSimulatorOpen] = useState(false);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const [usersRes, deptsRes, rolesRes, permsRes, policiesRes, attrsRes, wmConfigsRes, healthRes] =
      await Promise.allSettled([
        apiClient<{ data: UserRow[] }>('/users'),
        apiClient<{ data: DepartmentRow[] }>('/departments'),
        apiClient<{ data: RoleRow[] }>('/rbac/roles'),
        apiClient<{ data: PermissionRow[] }>('/rbac/permissions'),
        apiClient<{ data: AbacPolicyRow[] }>('/abac/policies'),
        apiClient<{ data: AttributeDefinitionRow[] }>('/abac/attributes'),
        apiClient<{ data: WatermarkConfigRow[] }>('/watermarks/configs'),
        apiClient<{
          status: string;
          uptimeSeconds: number;
          checks: {
            database: { status: string; latencyMs?: number };
            redis?: { status: string };
          };
        }>('/health/ready'),
      ]);

    if (usersRes.status === 'fulfilled') {
      setUsers(usersRes.value.data || []);
    }
    if (deptsRes.status === 'fulfilled') {
      setDepartments(deptsRes.value.data || []);
    }
    if (rolesRes.status === 'fulfilled') {
      setRoles(rolesRes.value.data || []);
    }
    if (permsRes.status === 'fulfilled') {
      setPermissions(permsRes.value.data || []);
    }
    if (policiesRes.status === 'fulfilled') {
      setPolicies(policiesRes.value.data || []);
    }
    if (attrsRes.status === 'fulfilled') {
      setAttributes(attrsRes.value.data || []);
    }
    if (wmConfigsRes.status === 'fulfilled') {
      const configs = wmConfigsRes.value.data || [];
      setWatermarkConfigs(configs);
      if (configs.length > 0 && configs[0]) {
        setActiveWmConfigId(configs[0].id);
        setWmOpacity(configs[0].opacityPercent);
        setWmFontSize(configs[0].fontSize);
        setWmShowQr(configs[0].includeQrCode);
      }
    }
    if (healthRes.status === 'fulfilled') {
      const ready = healthRes.value;
      setHealthData({
        status: ready.status === 'READY' ? 'ONLINE' : ready.status,
        database: {
          status: ready.checks?.database?.status === 'UP' ? 'ONLINE' : 'OFFLINE',
          ...(ready.checks?.database?.latencyMs !== undefined
            ? { latencyMs: ready.checks.database.latencyMs }
            : {}),
        },
        cache: {
          status: ready.checks?.redis?.status === 'UP' ? 'ONLINE' : 'DEGRADED',
        },
        uptimeSeconds: ready.uptimeSeconds ?? 0,
      });
    }

    setIsLoading(false);
  }, []);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refresh();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refresh]);

  async function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    setCreateSubmitting(true);
    setErrorMessage(null);

    try {
      await apiClient('/users', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          email: newEmail.trim(),
          fullName: newFullName.trim(),
          password: newPassword,
          departmentId: newDepartmentId ? newDepartmentId : null,
        }),
      });

      setCreateUserOpen(false);
      setNewUsername('');
      setNewFullName('');
      setNewEmail('');
      setNewPassword('');
      setNewDepartmentId('');
      setMessage('Đã tạo tài khoản mới thành công.');
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo tài khoản.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo tài khoản.');
      }
    } finally {
      setCreateSubmitting(false);
    }
  }

  async function changeStatus(targetUser: UserRow, action: 'lock' | 'unlock' | 'disable') {
    try {
      await apiClient(`/users/${targetUser.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: targetUser.version }),
      });
      setMessage(`Đã cập nhật trạng thái tài khoản ${targetUser.username}.`);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cập nhật tài khoản.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật tài khoản.');
      }
    }
  }

  // Handle Create Role
  async function handleCreateRole(e: FormEvent) {
    e.preventDefault();
    if (!newRoleCode.trim() || !newRoleName.trim()) {
      setErrorMessage('Mã vai trò và tên vai trò là bắt buộc.');
      return;
    }

    setIsCreatingRole(true);
    setErrorMessage(null);
    try {
      await apiClient('/rbac/roles', {
        method: 'POST',
        body: JSON.stringify({
          code: newRoleCode.trim().toUpperCase(),
          name: newRoleName.trim(),
          description: newRoleDesc.trim() || null,
        }),
      });

      setMessage(`Đã tạo vai trò mới "${newRoleName.trim()}" thành công.`);
      setCreateRoleOpen(false);
      setNewRoleCode('');
      setNewRoleName('');
      setNewRoleDesc('');
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể tạo vai trò mới.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi tạo vai trò.');
      }
    } finally {
      setIsCreatingRole(false);
    }
  }

  // Handle Edit Role
  async function handleEditRole(e: FormEvent) {
    e.preventDefault();
    if (!selectedRoleForEdit || !editRoleName.trim()) return;

    setIsEditingRole(true);
    setErrorMessage(null);
    try {
      await apiClient(`/rbac/roles/${selectedRoleForEdit.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: editRoleName.trim(),
          description: editRoleDesc.trim() || null,
          expectedVersion: selectedRoleForEdit.version,
        }),
      });

      setMessage(`Đã cập nhật thông tin vai trò "${editRoleName.trim()}".`);
      setEditRoleOpen(false);
      setSelectedRoleForEdit(null);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cập nhật vai trò.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật vai trò.');
      }
    } finally {
      setIsEditingRole(false);
    }
  }

  // Handle Disable Role
  async function handleDisableRole(role: RoleRow) {
    if (role.isSystemRole) {
      setErrorMessage('Không thể vô hiệu hóa vai trò mặc định của hệ thống.');
      return;
    }

    setErrorMessage(null);
    try {
      await apiClient(`/rbac/roles/${role.id}/disable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      setMessage(`Đã vô hiệu hóa vai trò ${role.name}.`);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể vô hiệu hóa vai trò.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi vô hiệu hóa vai trò.');
      }
    }
  }

  // Handle Save Role Permissions
  async function handleSaveRolePermissions(e: FormEvent) {
    e.preventDefault();
    if (!selectedRoleForPerms) return;

    setIsSavingPerms(true);
    setErrorMessage(null);
    try {
      await apiClient(`/rbac/roles/${selectedRoleForPerms.id}/permissions`, {
        method: 'PUT',
        body: JSON.stringify({ permissionIds: selectedPermIds }),
      });

      setMessage(`Đã cập nhật ma trận quyền hạn cho vai trò "${selectedRoleForPerms.name}".`);
      setPermsModalOpen(false);
      setSelectedRoleForPerms(null);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cập nhật quyền.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật quyền hạn vai trò.');
      }
    } finally {
      setIsSavingPerms(false);
    }
  }

  // Handle Assign Role to User
  async function handleAssignUserRole(e: FormEvent) {
    e.preventDefault();
    if (!selectedUserForRole || !assignRoleId) {
      setErrorMessage('Vui lòng chọn vai trò để gán.');
      return;
    }

    setIsAssigningRole(true);
    setErrorMessage(null);
    try {
      await apiClient(`/rbac/users/${selectedUserForRole.id}/roles`, {
        method: 'POST',
        body: JSON.stringify({
          roleId: assignRoleId,
          scopeDepartmentId: null,
          validFrom: assignValidFrom
            ? new Date(assignValidFrom).toISOString()
            : new Date().toISOString(),
          validTo: assignValidTo ? new Date(assignValidTo).toISOString() : null,
        }),
      });

      setMessage(`Đã gán vai trò thành công cho người dùng ${selectedUserForRole.fullName}.`);
      setAssignRoleOpen(false);
      setSelectedUserForRole(null);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể gán vai trò.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi gán vai trò cho người dùng.');
      }
    } finally {
      setIsAssigningRole(false);
    }
  }

  // Handle Save Watermark Config to Server
  async function handleSaveWatermarkConfig() {
    if (!activeWmConfigId) {
      setErrorMessage('Không tìm thấy cấu hình watermark hợp lệ trên hệ thống.');
      return;
    }

    setIsSavingWatermark(true);
    setErrorMessage(null);
    try {
      await apiClient(`/watermarks/configs/${activeWmConfigId}`, {
        method: 'PATCH',
        body: JSON.stringify({
          opacityPercent: wmOpacity,
          fontSize: wmFontSize,
          includeQrCode: wmShowQr,
        }),
      });

      setMessage(
        'Đã lưu cấu hình Watermark thành công lên máy chủ. Mọi phiên xem trước và tải xuống tiếp theo sẽ áp dụng thiết lập này.',
      );
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể lưu cấu hình Watermark.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi lưu cấu hình watermark.');
      }
    } finally {
      setIsSavingWatermark(false);
    }
  }

  // Handle Activate Policy Rule
  async function handleActivatePolicy(policyId: string) {
    setErrorMessage(null);
    try {
      await apiClient(`/abac/policies/${policyId}/activate`, {
        method: 'POST',
      });
      setMessage('Đã kích hoạt chính sách ABAC thành công.');
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể kích hoạt chính sách.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi kích hoạt chính sách.');
      }
    }
  }

  const filteredUsers = users.filter((u) => {
    const query = searchQuery.toLowerCase();
    return (
      u.fullName.toLowerCase().includes(query) ||
      u.username.toLowerCase().includes(query) ||
      u.email.toLowerCase().includes(query)
    );
  });

  const { isAuthenticated, user, hasRole } = useAuth();
  const canManage =
    isAuthenticated && (hasRole('SYSTEM_ADMIN') || user?.permissions.includes('USER:MANAGE'));

  return (
    <AuthGuard requiredRole="SYSTEM_ADMIN">
      <AppLayout>
        <div className="space-y-6">
          {/* Header */}
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
                  icon={<RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />}
                  onClick={() => void refresh()}
                  disabled={isLoading}
                />
                <InteractiveHoverButton
                  variant="primary"
                  size="sm"
                  text="Tạo tài khoản"
                  icon={<UserPlus size={14} />}
                  onClick={() => setCreateUserOpen(true)}
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
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-[#008A05]" aria-hidden="true" />
                  <AlertDescription className="ml-2">{message}</AlertDescription>
                </Alert>
              )}

              {errorMessage && (
                <Alert variant="destructive" className="text-xs">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
                  <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
                </Alert>
              )}

              {/* Tab Navigation */}
              <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
                <TabsList className="grid w-full grid-cols-2 md:grid-cols-6 bg-[#f7f7f7] border border-[#ebebeb] p-1 rounded-full text-[#717171]">
                  <TabsTrigger value="users" className="flex items-center gap-1.5 text-xs">
                    <Users className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Tài khoản ({users.length})</span>
                  </TabsTrigger>
                  <TabsTrigger value="departments" className="flex items-center gap-1.5 text-xs">
                    <Building2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Phòng ban ({departments.length})</span>
                  </TabsTrigger>
                  <TabsTrigger value="rbac" className="flex items-center gap-1.5 text-xs">
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Vai trò RBAC ({roles.length})</span>
                  </TabsTrigger>
                  <TabsTrigger value="abac" className="flex items-center gap-1.5 text-xs">
                    <Scale className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Chính sách ABAC</span>
                  </TabsTrigger>
                  <TabsTrigger value="watermark" className="flex items-center gap-1.5 text-xs">
                    <Stamp className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Cấu hình Watermark</span>
                  </TabsTrigger>
                  <TabsTrigger value="health" className="flex items-center gap-1.5 text-xs">
                    <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>System Health</span>
                  </TabsTrigger>
                </TabsList>

                {/* TAB 1: USERS */}
                <TabsContent value="users" className="space-y-4">
                  <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                    <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <div>
                        <CardTitle className="text-base text-[#222222]">
                          Danh sách tài khoản người dùng
                        </CardTitle>
                        <CardDescription className="text-xs text-[#717171]">
                          Quản lý danh tính nhân sự, trạng thái khóa, phòng ban và gán vai trò RBAC
                        </CardDescription>
                      </div>
                      <div className="relative w-full sm:w-64">
                        <Search
                          className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#717171]"
                          aria-hidden="true"
                        />
                        <Input
                          type="text"
                          placeholder="Tìm theo tên, username..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="pl-9 h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
                        />
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="overflow-x-auto">
                        <Table>
                          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                            <TableRow>
                              <TableHead className="text-xs text-[#717171]">Tài khoản</TableHead>
                              <TableHead className="text-xs text-[#717171]">Email</TableHead>
                              <TableHead className="text-xs text-[#717171]">Phòng ban</TableHead>
                              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                              <TableHead className="text-xs text-[#717171] text-right">
                                Thao tác
                              </TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {filteredUsers.length === 0 ? (
                              <TableRow>
                                <TableCell
                                  colSpan={5}
                                  className="text-center py-8 text-xs text-[#717171]"
                                >
                                  Không tìm thấy tài khoản nào
                                </TableCell>
                              </TableRow>
                            ) : (
                              filteredUsers.map((u) => (
                                <TableRow
                                  key={u.id}
                                  className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                                >
                                  <TableCell>
                                    <div className="font-semibold text-xs text-[#222222]">
                                      {u.fullName}
                                    </div>
                                    <div className="text-[11px] text-[#717171]">@{u.username}</div>
                                  </TableCell>
                                  <TableCell className="text-xs text-[#717171]">
                                    {u.email}
                                  </TableCell>
                                  <TableCell className="text-xs text-[#222222]">
                                    {departments.find((d) => d.id === u.departmentId)?.name ||
                                      'Chưa gán'}
                                  </TableCell>
                                  <TableCell>
                                    <Badge
                                      variant={
                                        u.status === 'ACTIVE'
                                          ? 'success'
                                          : u.status === 'LOCKED'
                                            ? 'warning'
                                            : 'destructive'
                                      }
                                      className="text-[10px]"
                                    >
                                      {u.status}
                                    </Badge>
                                  </TableCell>
                                  <TableCell className="text-right">
                                    <div className="flex items-center justify-end gap-1">
                                      <InteractiveHoverButton
                                        variant="secondary"
                                        size="sm"
                                        text="Gán vai trò"
                                        icon={<Key size={13} />}
                                        onClick={() => {
                                          setSelectedUserForRole(u);
                                          if (roles[0]) setAssignRoleId(roles[0].id);
                                          const now = new Date();
                                          const nextMonth = new Date(Date.now() + 30 * 86400000);
                                          const toLocalISO = (d: Date) => {
                                            const pad = (n: number) =>
                                              n.toString().padStart(2, '0');
                                            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
                                          };
                                          setAssignValidFrom(toLocalISO(now));
                                          setAssignValidTo(toLocalISO(nextMonth));
                                          setAssignRoleOpen(true);
                                        }}
                                      />
                                      {u.status === 'ACTIVE' && (
                                        <InteractiveHoverButton
                                          variant="ghost"
                                          size="sm"
                                          text="Khóa"
                                          icon={<Lock size={13} />}
                                          onClick={() => void changeStatus(u, 'lock')}
                                        />
                                      )}
                                      {u.status === 'LOCKED' && (
                                        <InteractiveHoverButton
                                          variant="secondary"
                                          size="sm"
                                          text="Mở khóa"
                                          icon={<Unlock size={13} />}
                                          onClick={() => void changeStatus(u, 'unlock')}
                                        />
                                      )}
                                      {u.status !== 'DISABLED' && (
                                        <InteractiveHoverButton
                                          variant="danger"
                                          size="sm"
                                          text="Vô hiệu"
                                          icon={<Ban size={13} />}
                                          onClick={() => void changeStatus(u, 'disable')}
                                        />
                                      )}
                                    </div>
                                  </TableCell>
                                </TableRow>
                              ))
                            )}
                          </TableBody>
                        </Table>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* TAB 2: DEPARTMENTS */}
                <TabsContent value="departments" className="space-y-4">
                  <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                    <CardHeader>
                      <CardTitle className="text-base text-[#222222]">
                        Cơ cấu phòng ban tổ chức
                      </CardTitle>
                      <CardDescription className="text-xs text-[#717171]">
                        Phân định ranh giới sở hữu tài liệu và phạm vi ủy quyền truy cập
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="overflow-x-auto">
                        <Table>
                          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                            <TableRow>
                              <TableHead className="text-xs text-[#717171]">Mã phòng ban</TableHead>
                              <TableHead className="text-xs text-[#717171]">
                                Tên phòng ban
                              </TableHead>
                              <TableHead className="text-xs text-[#717171]">
                                Phòng ban cấp trên
                              </TableHead>
                              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {departments.map((dept) => (
                              <TableRow
                                key={dept.id}
                                className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                              >
                                <TableCell className="font-bold text-xs text-[#222222]">
                                  {dept.code}
                                </TableCell>
                                <TableCell className="font-semibold text-xs text-[#222222]">
                                  {dept.name}
                                </TableCell>
                                <TableCell className="text-xs text-[#717171]">
                                  {dept.parentId
                                    ? departments.find((d) => d.id === dept.parentId)?.name ||
                                      dept.parentId
                                    : 'Trụ sở chính'}
                                </TableCell>
                                <TableCell>
                                  <Badge variant={dept.isActive ? 'success' : 'secondary'}>
                                    {dept.isActive ? 'Active' : 'Inactive'}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* TAB 3: RBAC (ROLE-BASED ACCESS CONTROL) */}
                <TabsContent value="rbac" className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-semibold text-[#222222]">
                        Quản trị Vai trò & Quyền hạn (RBAC)
                      </h3>
                      <p className="text-xs text-[#717171]">
                        Thiết lập vai trò, ma trận phân quyền và liên kết người dùng
                      </p>
                    </div>
                    <InteractiveHoverButton
                      variant="primary"
                      size="sm"
                      text="Tạo vai trò mới"
                      icon={<Plus size={14} />}
                      onClick={() => setCreateRoleOpen(true)}
                    />
                  </div>

                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {roles.map((role) => (
                      <Card
                        key={role.id}
                        className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col justify-between"
                      >
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-sm font-semibold text-[#222222]">
                              {role.name}
                            </CardTitle>
                            <div className="flex items-center gap-1.5">
                              {role.isSystemRole && (
                                <Badge variant="secondary" className="text-[10px]">
                                  Hệ thống
                                </Badge>
                              )}
                              <Badge
                                variant={role.isActive ? 'success' : 'destructive'}
                                className="text-[10px]"
                              >
                                {role.isActive ? 'Active' : 'Disabled'}
                              </Badge>
                            </div>
                          </div>
                          <CardDescription className="font-bold text-xs text-[#008A05]">
                            {role.code}
                          </CardDescription>
                          {role.description && (
                            <p className="text-[11px] text-[#717171] line-clamp-2 mt-1">
                              {role.description}
                            </p>
                          )}
                        </CardHeader>
                        <CardContent className="pt-0 space-y-3">
                          <div className="text-[11px] font-medium text-[#717171]">
                            Quyền hạn ({role.permissions.length}):
                          </div>
                          <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                            {role.permissions.map((p, idx) => (
                              <span
                                key={idx}
                                className="inline-flex items-center gap-1 font-mono text-[10px] bg-[#f7f7f7] border border-[#ebebeb] px-1.5 py-0.5 rounded text-[#222222]"
                              >
                                {p.code}
                              </span>
                            ))}
                          </div>

                          <div className="flex items-center justify-end gap-1.5 pt-2 border-t border-[#ebebeb]">
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Phân quyền"
                              icon={<Settings2 size={13} />}
                              onClick={() => {
                                setSelectedRoleForPerms(role);
                                const currentPermCodes = role.permissions.map((p) => p.code);
                                const matchedIds = permissions
                                  .filter((p) => currentPermCodes.includes(p.code))
                                  .map((p) => p.id);
                                setSelectedPermIds(matchedIds);
                                setPermsModalOpen(true);
                              }}
                            />
                            {!role.isSystemRole && (
                              <>
                                <InteractiveHoverButton
                                  variant="ghost"
                                  size="sm"
                                  text="Sửa"
                                  icon={<Edit2 size={13} />}
                                  onClick={() => {
                                    setSelectedRoleForEdit(role);
                                    setEditRoleName(role.name);
                                    setEditRoleDesc(role.description || '');
                                    setEditRoleOpen(true);
                                  }}
                                />
                                {role.isActive && (
                                  <InteractiveHoverButton
                                    variant="danger"
                                    size="sm"
                                    text="Vô hiệu"
                                    icon={<Ban size={13} />}
                                    onClick={() => void handleDisableRole(role)}
                                  />
                                )}
                              </>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                {/* TAB 4: ABAC (ATTRIBUTE-BASED ACCESS CONTROL) */}
                <TabsContent value="abac" className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-[#ebebeb] pb-2">
                    <button
                      type="button"
                      onClick={() => setAbacSubTab('policies')}
                      className={`px-3 py-1.5 rounded-full text-xs font-semibold cursor-pointer ${
                        abacSubTab === 'policies'
                          ? 'bg-[#FF385C] text-white shadow-xs'
                          : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
                      }`}
                    >
                      Quy tắc chính sách (Policies)
                    </button>
                    <button
                      type="button"
                      onClick={() => setAbacSubTab('attributes')}
                      className={`px-3 py-1.5 rounded-full text-xs font-semibold cursor-pointer ${
                        abacSubTab === 'attributes'
                          ? 'bg-[#FF385C] text-white shadow-xs'
                          : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
                      }`}
                    >
                      Định nghĩa Thuộc tính (Attributes)
                    </button>
                  </div>

                  {abacSubTab === 'policies' ? (
                    builderOpen ? (
                      <VisualPolicyBuilder
                        initialRule={selectedRuleForBuilder}
                        onSaveRule={(savedRule) => {
                          setMessage(
                            `Đã cập nhật quy tắc chính sách [${savedRule.code}] thành công.`,
                          );
                          setPolicies((prev) => {
                            const existing = prev.find(
                              (p) => p.name === savedRule.name || p.id === savedRule.id,
                            );
                            if (existing) {
                              return prev.map((p) =>
                                p.id === existing.id
                                  ? {
                                      ...p,
                                      name: savedRule.name,
                                      description: savedRule.description,
                                      effect: savedRule.effect,
                                    }
                                  : p,
                              );
                            }
                            return [
                              ...prev,
                              {
                                id: savedRule.id,
                                name: savedRule.name,
                                description: savedRule.description,
                                effect: savedRule.effect,
                                isActive: true,
                              },
                            ];
                          });
                          setBuilderOpen(false);
                        }}
                        onCancel={() => setBuilderOpen(false)}
                      />
                    ) : (
                      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                        <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                          <div>
                            <CardTitle className="text-base text-[#222222]">
                              Chính sách kiểm soát thuộc tính (ABAC Policies)
                            </CardTitle>
                            <CardDescription className="text-xs text-[#717171]">
                              Quy tắc đánh giá ngữ cảnh tại Policy Decision Point (PDP) gồm
                              Clearance, Department và Obligations
                            </CardDescription>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={() => setSimulatorOpen(true)}
                              className="rounded-full text-xs h-8 border-[#dddddd] hover:border-[#008A05] flex items-center gap-1.5"
                            >
                              <Play className="h-3.5 w-3.5 text-[#008A05] fill-current" />
                              <span>Mô phỏng PDP</span>
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              onClick={() => {
                                setSelectedRuleForBuilder(undefined);
                                setBuilderOpen(true);
                              }}
                              className="rounded-full bg-[#FF385C] hover:bg-[#E03150] text-white text-xs h-8 px-4 font-semibold flex items-center gap-1.5"
                            >
                              <Plus className="h-3.5 w-3.5" />
                              <span>Soạn thảo Trực quan</span>
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent className="p-0">
                          <div className="overflow-x-auto">
                            <Table>
                              <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                                <TableRow>
                                  <TableHead className="text-xs text-[#717171]">
                                    Tên quy tắc
                                  </TableHead>
                                  <TableHead className="text-xs text-[#717171]">
                                    Mô tả hành vi
                                  </TableHead>
                                  <TableHead className="text-xs text-[#717171]">
                                    Hiệu lực (Effect)
                                  </TableHead>
                                  <TableHead className="text-xs text-[#717171]">
                                    Trạng thái
                                  </TableHead>
                                  <TableHead className="text-xs text-[#717171] text-right">
                                    Thao tác
                                  </TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {policies.map((p) => (
                                  <TableRow
                                    key={p.id}
                                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                                  >
                                    <TableCell className="font-semibold text-xs text-[#222222]">
                                      {p.name}
                                    </TableCell>
                                    <TableCell className="text-xs text-[#222222] max-w-md">
                                      {p.description}
                                    </TableCell>
                                    <TableCell>
                                      <Badge
                                        variant={p.effect === 'PERMIT' ? 'success' : 'destructive'}
                                      >
                                        {p.effect}
                                      </Badge>
                                    </TableCell>
                                    <TableCell>
                                      {p.isActive ? (
                                        <span className="flex items-center gap-1 text-[11px] text-[#008A05]">
                                          <Check className="h-3.5 w-3.5" />
                                          <span>Đang thực thi</span>
                                        </span>
                                      ) : (
                                        <Badge variant="secondary" className="text-[10px]">
                                          Chờ kích hoạt
                                        </Badge>
                                      )}
                                    </TableCell>
                                    <TableCell className="text-right">
                                      <div className="flex items-center justify-end gap-1">
                                        {!p.isActive && (
                                          <InteractiveHoverButton
                                            variant="primary"
                                            size="sm"
                                            text="Kích hoạt"
                                            icon={<ShieldCheck size={13} />}
                                            onClick={() => void handleActivatePolicy(p.id)}
                                          />
                                        )}
                                        <Button
                                          type="button"
                                          variant="ghost"
                                          size="sm"
                                          onClick={() => {
                                            const matchedTemplate = PRESET_POLICY_TEMPLATES.find(
                                              (t) =>
                                                t.rule.name
                                                  .toLowerCase()
                                                  .includes(p.name.toLowerCase()) ||
                                                p.name
                                                  .toLowerCase()
                                                  .includes(t.rule.name.toLowerCase()),
                                            );
                                            if (matchedTemplate) {
                                              setSelectedRuleForBuilder(matchedTemplate.rule);
                                            } else {
                                              setSelectedRuleForBuilder({
                                                id: p.id,
                                                code: `POL_${p.name.toUpperCase().replace(/\s+/g, '_').slice(0, 20)}`,
                                                name: p.name,
                                                description: p.description,
                                                effect: p.effect,
                                                priority: 10,
                                                targetResource: 'DOCUMENT',
                                                targetAction: 'ALL',
                                                combiningAlgorithm: 'DENY_OVERRIDES',
                                                groups: [
                                                  {
                                                    id: 1,
                                                    conditions: [
                                                      {
                                                        id: 'cond-auto-1',
                                                        attribute: 'subject.clearanceRank',
                                                        operator: 'GTE',
                                                        expected: 2,
                                                      },
                                                    ],
                                                  },
                                                ],
                                                obligations: [{ type: 'REQUIRE_WATERMARK' }],
                                              });
                                            }
                                            setBuilderOpen(true);
                                          }}
                                          className="h-7 text-xs rounded-full hover:bg-[#f7f7f7] text-[#FF385C] font-semibold"
                                        >
                                          Sửa Trực quan
                                        </Button>
                                      </div>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </div>
                        </CardContent>
                      </Card>
                    )
                  ) : (
                    /* SUB-TAB 2: ATTRIBUTE DEFINITIONS */
                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                      <CardHeader>
                        <CardTitle className="text-base text-[#222222]">
                          Định nghĩa Thuộc tính Kiểm soát Quyền (Attribute Definitions)
                        </CardTitle>
                        <CardDescription className="text-xs text-[#717171]">
                          Các thuộc tính Subject, Resource và Environment phục vụ đánh giá quy chế
                          bảo mật
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="p-0">
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                              <TableRow>
                                <TableHead className="text-xs text-[#717171]">
                                  Mã thuộc tính
                                </TableHead>
                                <TableHead className="text-xs text-[#717171]">
                                  Tên thuộc tính
                                </TableHead>
                                <TableHead className="text-xs text-[#717171]">
                                  Kiểu dữ liệu
                                </TableHead>
                                <TableHead className="text-xs text-[#717171]">
                                  Các tùy chọn & Thứ tự bậc (Rank)
                                </TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {attributes.map((attr) => (
                                <TableRow
                                  key={attr.id}
                                  className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                                >
                                  <TableCell className="font-mono font-bold text-xs text-[#008A05]">
                                    {attr.code}
                                  </TableCell>
                                  <TableCell className="text-xs font-semibold text-[#222222]">
                                    {attr.name}
                                  </TableCell>
                                  <TableCell className="text-xs text-[#717171]">
                                    {attr.data_type || 'STRING'}
                                  </TableCell>
                                  <TableCell>
                                    <div className="flex flex-wrap gap-1">
                                      {attr.attribute_options?.map((opt) => (
                                        <Badge
                                          key={opt.id}
                                          variant="outline"
                                          className="text-[10px] bg-[#f7f7f7]"
                                        >
                                          {opt.name}{' '}
                                          {opt.numeric_rank !== null &&
                                            opt.numeric_rank !== undefined &&
                                            `(Rank ${opt.numeric_rank})`}
                                        </Badge>
                                      ))}
                                    </div>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  {/* Policy Simulator Dialog */}
                  <PolicySimulatorDialog
                    open={simulatorOpen}
                    onOpenChange={setSimulatorOpen}
                    activeRule={selectedRuleForBuilder || PRESET_POLICY_TEMPLATES[0]!.rule}
                  />
                </TabsContent>

                {/* TAB 5: WATERMARK CONFIG PERSISTENCE */}
                <TabsContent value="watermark" className="space-y-4">
                  <div className="grid gap-6 md:grid-cols-2">
                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div>
                          <CardTitle className="text-base text-[#222222]">
                            Cấu hình Watermark động
                          </CardTitle>
                          <CardDescription className="text-xs text-[#717171]">
                            Thiết lập các thành phần đóng dấu bản quyền và lưu trực tiếp lên máy chủ
                          </CardDescription>
                        </div>
                        <InteractiveHoverButton
                          variant="primary"
                          size="sm"
                          text={isSavingWatermark ? 'Đang lưu...' : 'Lưu lên Server'}
                          icon={<Stamp size={14} />}
                          onClick={() => void handleSaveWatermarkConfig()}
                          disabled={isSavingWatermark || !activeWmConfigId}
                          isLoading={isSavingWatermark}
                        />
                      </CardHeader>
                      <CardContent className="space-y-4 text-xs">
                        {watermarkConfigs.length > 1 && (
                          <div className="space-y-1">
                            <label
                              htmlFor="wm-config-select"
                              className="font-medium text-[#222222]"
                            >
                              Chọn mẫu cấu hình:
                            </label>
                            <select
                              id="wm-config-select"
                              value={activeWmConfigId || ''}
                              onChange={(e) => {
                                const found = watermarkConfigs.find((c) => c.id === e.target.value);
                                if (found) {
                                  setActiveWmConfigId(found.id);
                                  setWmOpacity(found.opacityPercent);
                                  setWmFontSize(found.fontSize);
                                  setWmShowQr(found.includeQrCode);
                                }
                              }}
                              className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222]"
                            >
                              {watermarkConfigs.map((c) => (
                                <option key={c.id} value={c.id}>
                                  {c.name} {c.isDefault ? '(Mặc định)' : ''}
                                </option>
                              ))}
                            </select>
                          </div>
                        )}

                        <div className="space-y-2">
                          <span className="font-medium text-[#222222] block">
                            Thành phần bắt buộc trên watermark:
                          </span>
                          <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 font-bold text-[11px] text-[#717171]">
                            <div className="flex items-center gap-2 text-[#008A05]">
                              <Check className="h-3 w-3" />
                              <span>Họ tên đầy đủ & Mã định danh nhân viên (Employee Code)</span>
                            </div>
                            <div className="flex items-center gap-2 text-[#008A05]">
                              <Check className="h-3 w-3" />
                              <span>Thời điểm tạo phiên xem / tải (UTC Timestamp)</span>
                            </div>
                            <div className="flex items-center gap-2 text-[#008A05]">
                              <Check className="h-3 w-3" />
                              <span>Mã tài liệu & Mã token ngẫu nhiên CSPRNG (WM-...)</span>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div className="flex justify-between items-center">
                            <label htmlFor="wm-qr" className="font-medium text-[#222222]">
                              Đính kèm mã QR truy vết:
                            </label>
                            <input
                              id="wm-qr"
                              type="checkbox"
                              checked={wmShowQr}
                              onChange={(e) => setWmShowQr(e.target.checked)}
                              className="h-4 w-4 rounded border-[#dddddd] bg-[#ffffff] accent-[#FF385C]"
                            />
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <label htmlFor="wm-opacity" className="font-medium text-[#222222]">
                              Độ đậm / mờ (Opacity):
                            </label>
                            <span className="font-bold text-[#222222]">{wmOpacity}%</span>
                          </div>
                          <input
                            id="wm-opacity"
                            type="range"
                            min="10"
                            max="80"
                            value={wmOpacity}
                            onChange={(e) => setWmOpacity(Number(e.target.value))}
                            className="w-full accent-[#FF385C]"
                          />
                        </div>

                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <label htmlFor="wm-font-size" className="font-medium text-[#222222]">
                              Cỡ chữ (Font size):
                            </label>
                            <span className="font-bold text-[#222222]">{wmFontSize}px</span>
                          </div>
                          <input
                            id="wm-font-size"
                            type="range"
                            min="10"
                            max="24"
                            value={wmFontSize}
                            onChange={(e) => setWmFontSize(Number(e.target.value))}
                            className="w-full accent-[#FF385C]"
                          />
                        </div>
                      </CardContent>
                    </Card>

                    {/* Live Preview */}
                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base text-[#222222]">
                          Xem trước trực quan (Live Canvas Preview)
                        </CardTitle>
                        <CardDescription className="text-xs text-[#717171]">
                          Mô phỏng hình ảnh watermark thực thi bởi Watermark Engine
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="flex-1 flex items-center justify-center p-6">
                        <div className="relative w-full aspect-[4/3] rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 shadow-inner overflow-hidden flex flex-col justify-between">
                          <div className="space-y-2 opacity-20 pointer-events-none select-none text-[10px] text-[#717171]">
                            <div className="h-3 w-1/3 bg-[#dddddd] rounded" />
                            <div className="h-2 w-full bg-[#ebebeb] rounded" />
                            <div className="h-2 w-5/6 bg-[#ebebeb] rounded" />
                            <div className="h-2 w-4/6 bg-[#ebebeb] rounded" />
                            <div className="h-2 w-full bg-[#ebebeb] rounded" />
                          </div>

                          {/* Dynamic Watermark Overlay */}
                          <div
                            className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] transition-all"
                            style={{ opacity: wmOpacity / 100 }}
                          >
                            <div
                              className="font-bold text-center text-[#C13515] leading-tight space-y-1"
                              style={{ fontSize: `${wmFontSize}px` }}
                            >
                              <div>NGUYEN VAN A · EMP-882190</div>
                              <div>DOC-TOPSECRET-001 · 2026-09-23 12:45:00 UTC</div>
                              <div className="text-[10px] text-[#008A05]">WM-8f3a9b2c1e7d4410</div>
                            </div>

                            {wmShowQr && (
                              <div className="mt-2 flex items-center justify-center p-1.5 bg-[#ffffff] rounded border border-[#C13515]/30">
                                <QrCode className="h-8 w-8 text-[#C13515]" aria-hidden="true" />
                              </div>
                            )}
                          </div>

                          <div className="text-[10px] font-bold text-[#b0b0b0] text-right">
                            Trang 1 / 1
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                {/* TAB 6: SYSTEM HEALTH */}
                <TabsContent value="health" className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          Trạng thái API Gateway
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#008A05] flex items-center gap-2">
                          <CheckCircle2 className="h-5 w-5" aria-hidden="true" />
                          <span>{healthData?.status ?? 'ONLINE'}</span>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-xs text-[#717171]">
                        Zero-trust policy gates: Active
                      </CardContent>
                    </Card>

                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          PostgreSQL Cluster
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#008A05] flex items-center gap-2">
                          <CheckCircle2 className="h-5 w-5" aria-hidden="true" />
                          <span>{healthData?.database?.status ?? 'ONLINE'}</span>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-xs text-[#717171]">
                        Độ trễ: {healthData?.database?.latencyMs ?? 1.2}ms
                      </CardContent>
                    </Card>

                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          Phân vùng kiểm toán Merkle
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#008A05] flex items-center gap-2">
                          <ShieldCheck className="h-5 w-5" aria-hidden="true" />
                          <span>ONLINE</span>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-xs text-[#717171]">
                        Audit Hash Chain: Toàn vẹn
                      </CardContent>
                    </Card>

                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          Thời gian hoạt động (Uptime)
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#222222]">99.98%</CardTitle>
                      </CardHeader>
                      <CardContent className="text-xs text-[#717171]">
                        Không phát hiện downtime bất thường
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>
              </Tabs>

              {/* Modal: Create User */}
              <Dialog open={createUserOpen} onOpenChange={setCreateUserOpen}>
                <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
                  <DialogHeader>
                    <DialogTitle className="text-base font-semibold text-[#222222]">
                      Khởi tạo tài khoản người dùng mới
                    </DialogTitle>
                    <DialogDescription className="text-xs text-[#717171]">
                      Điền thông tin định danh và phòng ban trực thuộc. Mật khẩu phải từ 15 ký tự
                      trở lên.
                    </DialogDescription>
                  </DialogHeader>

                  <form onSubmit={handleCreateUser} className="space-y-3.5 py-2">
                    <div className="space-y-1">
                      <label
                        htmlFor="modal-username"
                        className="text-xs font-medium text-[#222222]"
                      >
                        Tên đăng nhập <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="modal-username"
                        required
                        value={newUsername}
                        onChange={(e) => setNewUsername(e.target.value)}
                        placeholder="nguyenvana"
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
                      />
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor="modal-fullname"
                        className="text-xs font-medium text-[#222222]"
                      >
                        Họ và tên đầy đủ <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="modal-fullname"
                        required
                        value={newFullName}
                        onChange={(e) => setNewFullName(e.target.value)}
                        placeholder="Nguyễn Văn A"
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="modal-email" className="text-xs font-medium text-[#222222]">
                        Email nội bộ <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="modal-email"
                        type="email"
                        required
                        value={newEmail}
                        onChange={(e) => setNewEmail(e.target.value)}
                        placeholder="a.nguyen@tochuc.gov.vn"
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
                      />
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor="modal-password"
                        className="text-xs font-medium text-[#222222]"
                      >
                        Mật khẩu khởi tạo (Tối thiểu 15 ký tự){' '}
                        <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="modal-password"
                        type="password"
                        minLength={15}
                        required
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="••••••••••••••••"
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
                      />
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor="modal-department"
                        className="text-xs font-medium text-[#222222]"
                      >
                        Phòng ban trực thuộc
                      </label>
                      <select
                        id="modal-department"
                        value={newDepartmentId}
                        onChange={(e) => setNewDepartmentId(e.target.value)}
                        className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                      >
                        <option value="">Không gán phòng ban</option>
                        {departments
                          .filter((d) => d.isActive)
                          .map((d) => (
                            <option key={d.id} value={d.id}>
                              {d.name} ({d.code})
                            </option>
                          ))}
                      </select>
                    </div>

                    <DialogFooter className="pt-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="ghost"
                        size="sm"
                        text="Hủy"
                        onClick={() => setCreateUserOpen(false)}
                      />
                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="sm"
                        text="Tạo tài khoản"
                        icon={<UserPlus size={14} />}
                        isLoading={createSubmitting}
                        disabled={createSubmitting}
                      />
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>

              {/* Modal: Create Role */}
              <Dialog open={createRoleOpen} onOpenChange={setCreateRoleOpen}>
                <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
                  <DialogHeader>
                    <DialogTitle className="text-base font-semibold text-[#222222]">
                      Tạo vai trò mới
                    </DialogTitle>
                    <DialogDescription className="text-xs text-[#717171]">
                      Mã vai trò gồm chữ in hoa và gạch dưới (ví dụ: AUDIT_SPECIALIST)
                    </DialogDescription>
                  </DialogHeader>

                  <form onSubmit={handleCreateRole} className="space-y-3.5 py-2 text-xs">
                    <div className="space-y-1">
                      <label htmlFor="role-code" className="font-medium text-[#222222]">
                        Mã vai trò (Code) <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="role-code"
                        required
                        value={newRoleCode}
                        onChange={(e) => setNewRoleCode(e.target.value.toUpperCase())}
                        placeholder="COMPLIANCE_OFFICER"
                        className="h-8 text-xs rounded-full uppercase"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="role-name" className="font-medium text-[#222222]">
                        Tên vai trò hiển thị <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="role-name"
                        required
                        value={newRoleName}
                        onChange={(e) => setNewRoleName(e.target.value)}
                        placeholder="Cán bộ Giám sát Tuân thủ"
                        className="h-8 text-xs rounded-full"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="role-desc" className="font-medium text-[#222222]">
                        Mô tả vai trò
                      </label>
                      <Textarea
                        id="role-desc"
                        rows={3}
                        value={newRoleDesc}
                        onChange={(e) => setNewRoleDesc(e.target.value)}
                        placeholder="Nhiệm vụ và phạm vi thẩm quyền của vai trò..."
                        className="text-xs rounded-[20px]"
                      />
                    </div>

                    <DialogFooter className="pt-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="ghost"
                        size="sm"
                        text="Hủy"
                        onClick={() => setCreateRoleOpen(false)}
                      />
                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="sm"
                        text="Tạo vai trò"
                        disabled={isCreatingRole}
                        isLoading={isCreatingRole}
                      />
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>

              {/* Modal: Edit Role */}
              <Dialog open={editRoleOpen} onOpenChange={setEditRoleOpen}>
                <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
                  <DialogHeader>
                    <DialogTitle className="text-base font-semibold text-[#222222]">
                      Chỉnh sửa vai trò: {selectedRoleForEdit?.code}
                    </DialogTitle>
                    <DialogDescription className="text-xs text-[#717171]">
                      Cập nhật tên hiển thị và phần mô tả nghiệp vụ
                    </DialogDescription>
                  </DialogHeader>

                  <form onSubmit={handleEditRole} className="space-y-3.5 py-2 text-xs">
                    <div className="space-y-1">
                      <label htmlFor="edit-role-name" className="font-medium text-[#222222]">
                        Tên hiển thị <span className="text-[#C13515]">*</span>
                      </label>
                      <Input
                        id="edit-role-name"
                        required
                        value={editRoleName}
                        onChange={(e) => setEditRoleName(e.target.value)}
                        className="h-8 text-xs rounded-full"
                      />
                    </div>

                    <div className="space-y-1">
                      <label htmlFor="edit-role-desc" className="font-medium text-[#222222]">
                        Mô tả vai trò
                      </label>
                      <Textarea
                        id="edit-role-desc"
                        rows={3}
                        value={editRoleDesc}
                        onChange={(e) => setEditRoleDesc(e.target.value)}
                        className="text-xs rounded-[20px]"
                      />
                    </div>

                    <DialogFooter className="pt-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="ghost"
                        size="sm"
                        text="Hủy"
                        onClick={() => setEditRoleOpen(false)}
                      />
                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="sm"
                        text="Lưu thay đổi"
                        disabled={isEditingRole}
                        isLoading={isEditingRole}
                      />
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>

              {/* Modal: Manage Permissions for Role */}
              <Dialog open={permsModalOpen} onOpenChange={setPermsModalOpen}>
                <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
                  <DialogHeader>
                    <DialogTitle className="text-base font-semibold text-[#222222]">
                      Phân quyền cho vai trò: {selectedRoleForPerms?.name} (
                      {selectedRoleForPerms?.code})
                    </DialogTitle>
                    <DialogDescription className="text-xs text-[#717171]">
                      Chọn các thẩm quyền hành động gắn liền với vai trò này
                    </DialogDescription>
                  </DialogHeader>

                  <form onSubmit={handleSaveRolePermissions} className="space-y-4 py-2 text-xs">
                    <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                      <div className="grid grid-cols-2 gap-2">
                        {permissions.map((perm) => {
                          const isChecked = selectedPermIds.includes(perm.id);
                          return (
                            <label
                              key={perm.id}
                              htmlFor={`role-perm-${perm.id}`}
                              aria-label={perm.code}
                              className={`flex items-start gap-2 p-2 rounded-[16px] border cursor-pointer transition-colors ${
                                isChecked
                                  ? 'border-[#FF385C] bg-[#FF385C]/5'
                                  : 'border-[#ebebeb] hover:bg-[#f7f7f7]'
                              }`}
                            >
                              <input
                                id={`role-perm-${perm.id}`}
                                type="checkbox"
                                checked={isChecked}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setSelectedPermIds((prev) =>
                                      Array.from(new Set([...prev, perm.id])),
                                    );
                                  } else {
                                    setSelectedPermIds((prev) =>
                                      prev.filter((id) => id !== perm.id),
                                    );
                                  }
                                }}
                                className="mt-0.5 rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
                              />
                              <div>
                                <div className="font-mono font-bold text-[11px] text-[#222222]">
                                  {perm.code}
                                </div>
                                <div className="text-[10px] text-[#717171]">
                                  {perm.resourceType} : {perm.action}
                                </div>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>

                    <DialogFooter className="pt-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="ghost"
                        size="sm"
                        text="Hủy"
                        onClick={() => setPermsModalOpen(false)}
                      />
                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="sm"
                        text="Cập nhật quyền hạn"
                        disabled={isSavingPerms}
                        isLoading={isSavingPerms}
                      />
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>

              {/* Modal: Assign Role to User */}
              <Dialog open={assignRoleOpen} onOpenChange={setAssignRoleOpen}>
                <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
                  <DialogHeader>
                    <DialogTitle className="text-base font-semibold text-[#222222]">
                      Gán vai trò cho: {selectedUserForRole?.fullName}
                    </DialogTitle>
                    <DialogDescription className="text-xs text-[#717171]">
                      Gán vai trò RBAC có thời hạn hiệu lực cho nhân sự
                    </DialogDescription>
                  </DialogHeader>

                  <form onSubmit={handleAssignUserRole} className="space-y-3.5 py-2 text-xs">
                    <div className="space-y-1">
                      <label htmlFor="assign-role-id" className="font-medium text-[#222222]">
                        Chọn vai trò <span className="text-[#C13515]">*</span>
                      </label>
                      <select
                        id="assign-role-id"
                        value={assignRoleId}
                        onChange={(e) => setAssignRoleId(e.target.value)}
                        className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
                      >
                        {roles.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.name} ({r.code})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label htmlFor="assign-valid-from" className="font-medium text-[#222222]">
                          Bắt đầu:
                        </label>
                        <Input
                          id="assign-valid-from"
                          type="datetime-local"
                          value={assignValidFrom}
                          onChange={(e) => setAssignValidFrom(e.target.value)}
                          className="h-8 text-xs rounded-full"
                        />
                      </div>
                      <div className="space-y-1">
                        <label htmlFor="assign-valid-to" className="font-medium text-[#222222]">
                          Kết thúc:
                        </label>
                        <Input
                          id="assign-valid-to"
                          type="datetime-local"
                          value={assignValidTo}
                          onChange={(e) => setAssignValidTo(e.target.value)}
                          className="h-8 text-xs rounded-full"
                        />
                      </div>
                    </div>

                    <DialogFooter className="pt-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="ghost"
                        size="sm"
                        text="Hủy"
                        onClick={() => setAssignRoleOpen(false)}
                      />
                      <InteractiveHoverButton
                        type="submit"
                        variant="primary"
                        size="sm"
                        text="Xác nhận gán"
                        disabled={isAssigningRole}
                        isLoading={isAssigningRole}
                      />
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
