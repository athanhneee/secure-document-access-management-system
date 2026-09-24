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
  isSystemRole: boolean;
  isActive: boolean;
  permissions: Array<{ code: string; name?: string }>;
}

interface AbacPolicyRow {
  id: string;
  name: string;
  description: string;
  effect: 'PERMIT' | 'DENY';
  isActive: boolean;
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
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
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

  // Watermark interactive preview state
  const [wmShowQr, setWmShowQr] = useState(true);
  const [wmOpacity, setWmOpacity] = useState(25);
  const [wmFontSize, setWmFontSize] = useState(14);

  // Visual Policy Builder & Simulator states
  const [builderOpen, setBuilderOpen] = useState(false);
  const [selectedRuleForBuilder, setSelectedRuleForBuilder] = useState<
    VisualPolicyRule | undefined
  >(undefined);
  const [simulatorOpen, setSimulatorOpen] = useState(false);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [userData, departmentData, roleData] = await Promise.all([
        apiClient<{ data: UserRow[] }>('/users').catch(() => ({ data: [] })),
        apiClient<{ data: DepartmentRow[] }>('/departments').catch(() => ({ data: [] })),
        apiClient<{ data: RoleRow[] }>('/rbac/roles').catch(() => ({ data: [] })),
      ]);

      setUsers(userData.data || []);
      setDepartments(departmentData.data || []);
      setRoles(roleData.data || []);

      // Load ABAC policies
      try {
        const policyData = await apiClient<{ data: AbacPolicyRow[] }>('/abac/policies');
        setPolicies(policyData.data || []);
      } catch {
        setPolicies([]);
      }

      // Load System Health
      try {
        const ready = await apiClient<{
          status: string;
          uptimeSeconds: number;
          checks: {
            database: { status: string; latencyMs?: number };
            redis?: { status: string };
          };
        }>('/health/ready');
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
      } catch {
        setHealthData({
          status: 'DEGRADED',
          database: { status: 'UNKNOWN' },
          cache: { status: 'UNKNOWN' },
          uptimeSeconds: 0,
        });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể tải không gian quản trị.');
      }
    } finally {
      setIsLoading(false);
    }
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

  async function changeStatus(user: UserRow, action: 'lock' | 'unlock' | 'disable') {
    try {
      await apiClient(`/users/${user.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: user.version }),
      });
      setMessage(`Đã cập nhật trạng thái tài khoản ${user.username}.`);
      await refresh();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể cập nhật tài khoản.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi cập nhật tài khoản.');
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
                Users · Departments · RBAC
              </h1>
              <p className="text-xs text-[#717171]">
                Quản lý người dùng, phòng ban, ma trận phân quyền RBAC/ABAC, watermark và sức khỏe
                hệ thống
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
                    <span>Vai trò RBAC</span>
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
                          Tất cả danh tính nhân sự, trạng thái khóa và phòng ban trực thuộc
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
                              <TableHead className="text-xs text-[#717171]">
                                Họ và tên / Username
                              </TableHead>
                              <TableHead className="text-xs text-[#717171]">Email</TableHead>
                              <TableHead className="text-xs text-[#717171]">Phòng ban</TableHead>
                              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                              <TableHead className="text-xs text-[#717171] text-right">
                                Thao tác quản trị
                              </TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {filteredUsers.length === 0 ? (
                              <TableRow>
                                <TableCell
                                  colSpan={5}
                                  className="text-center py-8 text-[#717171] text-xs"
                                >
                                  Không tìm thấy người dùng nào phù hợp
                                </TableCell>
                              </TableRow>
                            ) : (
                              filteredUsers.map((user) => {
                                const dept = departments.find((d) => d.id === user.departmentId);
                                return (
                                  <TableRow
                                    key={user.id}
                                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                                  >
                                    <TableCell>
                                      <div className="font-medium text-[#222222] text-xs">
                                        {user.fullName}
                                      </div>
                                      <div className="text-[11px] font-bold text-[#717171]">
                                        {user.username}
                                      </div>
                                    </TableCell>
                                    <TableCell className="text-xs text-[#222222]">
                                      {user.email}
                                    </TableCell>
                                    <TableCell className="text-xs text-[#222222]">
                                      {dept ? (
                                        dept.name
                                      ) : (
                                        <span className="text-[#717171] italic">Chưa gán</span>
                                      )}
                                    </TableCell>
                                    <TableCell>
                                      <Badge
                                        variant={
                                          user.status === 'ACTIVE'
                                            ? 'success'
                                            : user.status === 'LOCKED'
                                              ? 'warning'
                                              : 'destructive'
                                        }
                                      >
                                        {user.status}
                                      </Badge>
                                    </TableCell>
                                    <TableCell className="text-right">
                                      <div className="flex items-center justify-end gap-1.5">
                                        {user.status === 'ACTIVE' && (
                                          <InteractiveHoverButton
                                            size="sm"
                                            variant="secondary"
                                            text="Khóa"
                                            icon={<Lock size={14} />}
                                            onClick={() => void changeStatus(user, 'lock')}
                                            title="Khóa tài khoản tạm thời"
                                          />
                                        )}
                                        {user.status === 'LOCKED' && (
                                          <InteractiveHoverButton
                                            size="sm"
                                            variant="secondary"
                                            text="Mở khóa"
                                            icon={<Unlock size={14} />}
                                            onClick={() => void changeStatus(user, 'unlock')}
                                            title="Mở khóa tài khoản"
                                          />
                                        )}
                                        {user.status !== 'DISABLED' && (
                                          <InteractiveHoverButton
                                            size="sm"
                                            variant="danger"
                                            text="Vô hiệu"
                                            icon={<Ban size={14} />}
                                            onClick={() => void changeStatus(user, 'disable')}
                                            title="Vô hiệu hóa tài khoản"
                                          />
                                        )}
                                      </div>
                                    </TableCell>
                                  </TableRow>
                                );
                              })
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

                {/* TAB 3: RBAC */}
                <TabsContent value="rbac" className="space-y-4">
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
                            {role.isSystemRole && <Badge variant="secondary">System Role</Badge>}
                          </div>
                          <CardDescription className="font-bold text-xs text-[#008A05]">
                            {role.code}
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="pt-0 space-y-2">
                          <div className="text-[11px] font-medium text-[#717171]">
                            Thẩm quyền được cấp:
                          </div>
                          <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                            {role.permissions.map((p, idx) => (
                              <span
                                key={idx}
                                className="staff-badge inline-flex items-center gap-1 font-bold text-[10px] text-[#222222] mr-2 mb-1"
                                style={{ background: 'transparent', border: 'none', padding: 0 }}
                              >
                                <span className="dot dot-neutral" aria-hidden="true" />
                                <span>{p.code}</span>
                              </span>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                {/* TAB 4: ABAC */}
                <TabsContent value="abac" className="space-y-4">
                  {builderOpen ? (
                    <VisualPolicyBuilder
                      initialRule={selectedRuleForBuilder}
                      onSaveRule={(savedRule) => {
                        setMessage(
                          `Đã cập nhật quy tắc chính sách [${savedRule.code}] thành công.`,
                        );
                        // Optimistically update or add policy
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
                            Quy tắc đánh giá ngữ cảnh tại Policy Decision Point (PDP) gồm Clearance,
                            Department và Obligations
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
                                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
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
                                    <span className="flex items-center gap-1 text-[11px] text-[#008A05]">
                                      <Check className="h-3.5 w-3.5" aria-hidden="true" />
                                      <span>Đang thực thi</span>
                                    </span>
                                  </TableCell>
                                  <TableCell className="text-right">
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => {
                                        // Find matched template or build visual rule
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

                {/* TAB 5: WATERMARK CONFIG */}
                <TabsContent value="watermark" className="space-y-4">
                  <div className="grid gap-6 md:grid-cols-2">
                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
                      <CardHeader>
                        <CardTitle className="text-base text-[#222222]">
                          Cấu hình Watermark động
                        </CardTitle>
                        <CardDescription className="text-xs text-[#717171]">
                          Thiết lập các thành phần đóng dấu bản quyền nhằm chống chụp ảnh và truy
                          vết rò rỉ
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4 text-xs">
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
                          Mô phỏng hình ảnh watermark khi xuất trang tài liệu mật
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="flex-1 flex items-center justify-center p-6">
                        <div className="relative w-full aspect-[4/3] rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 shadow-inner overflow-hidden flex flex-col justify-between">
                          {/* Document mockup content behind */}
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
                        Liveness & Readiness: 200 OK
                      </CardContent>
                    </Card>

                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          Cơ sở dữ liệu (Database)
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#008A05] flex items-center gap-2">
                          <CheckCircle2 className="h-5 w-5" aria-hidden="true" />
                          <span>{healthData?.database?.status ?? 'ONLINE'}</span>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="text-xs text-[#717171]">
                        Độ trễ: {healthData?.database?.latencyMs ?? 3}ms
                      </CardContent>
                    </Card>

                    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_4px_16px_rgba(0,0,0,0.03)]">
                      <CardHeader className="pb-2">
                        <CardDescription className="text-xs text-[#717171]">
                          Hàng đợi & Bộ nhớ Cache
                        </CardDescription>
                        <CardTitle className="text-xl font-bold text-[#008A05] flex items-center gap-2">
                          <CheckCircle2 className="h-5 w-5" aria-hidden="true" />
                          <span>{healthData?.cache?.status ?? 'ONLINE'}</span>
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
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
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
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
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
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
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
                        className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
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
            </>
          )}
        </div>
      </AppLayout>
    </AuthGuard>
  );
}
