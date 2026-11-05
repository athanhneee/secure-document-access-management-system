'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  applyOptimisticPolicyActivate,
  applyOptimisticRoleDisable,
  applyOptimisticUserStatus,
} from '@/lib/optimistic-state';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import {
  mapHealthReadyResponse,
  normalizeAbacPolicyRow,
  normalizeAttributeDefinitionRow,
} from '../helpers';
import type {
  AbacPolicyApiDto,
  AbacPolicyRow,
  AttributeDefinitionApiDto,
  AttributeDefinitionRow,
  DepartmentRow,
  HealthDashboardResponse,
  HealthReadyResponse,
  PermissionRow,
  RoleRow,
  SystemHealthData,
  UserRow,
  UserStatusAction,
  WatermarkConfigRow,
} from '../types';
import { useWatermarkSettings } from './use-watermark-settings';

/**
 * Thuật toán: Đồng bộ Song song Chịu lỗi Đa Phân hệ Quản trị & Kiểm soát Đồng thời Lạc quan (`useAdminData`)
 * Mục đích: Tải đồng thời các nguồn dữ liệu quản trị độc lập (bao gồm xử lý phản hồi sức khỏe 503 suy giảm) và đồng bộ chính sách ABAC trực tiếp lên máy chủ PDP.
 * Cơ chế hoạt động:
 *   - Sử dụng `Promise.allSettled` gom kết quả từ các điểm cuối để sự cố cục bộ ở một phân hệ không làm tê liệt bảng điều khiển; trích xuất thân JSON từ `ApiError.response` khi `/health/ready` trả mã `503`.
 *   - Gửi kèm `expectedVersion` (Optimistic Concurrency Control) khi cập nhật người dùng/vai trò và định tuyến `POST`/`PUT` `/abac/policies` theo định danh số thực tế.
 */
export function useAdminData() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const wm = useWatermarkSettings({
    onRefresh: async () => setRefreshTrigger((n) => n + 1),
    onSuccess: (msg) => {
      setErrorMessage(null);
      setMessage(msg);
    },
    onError: setErrorMessage,
  });
  const { hydrateConfigs } = wm;

  const refresh = useCallback(
    async (options?: { silent?: boolean }) => {
      if (!options?.silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);

      const [
        usersRes,
        deptsRes,
        rolesRes,
        permsRes,
        policiesRes,
        attrsRes,
        wmConfigsRes,
        healthRes,
        dashboardRes,
      ] = await Promise.allSettled([
        apiClient<{ data: UserRow[] }>('/users'),
        apiClient<{ data: DepartmentRow[] }>('/departments'),
        apiClient<{ data: RoleRow[] }>('/rbac/roles'),
        apiClient<{ data: PermissionRow[] }>('/rbac/permissions'),
        apiClient<{ data: AbacPolicyApiDto[] }>('/abac/policies'),
        apiClient<{ data: AttributeDefinitionApiDto[] }>('/abac/attributes'),
        apiClient<{ data: WatermarkConfigRow[] }>('/watermarks/configs'),
        apiClient<HealthReadyResponse>('/health/ready'),
        apiClient<HealthDashboardResponse>('/health/dashboard'),
      ]);

      if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data || []);
      if (deptsRes.status === 'fulfilled') setDepartments(deptsRes.value.data || []);
      if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value.data || []);
      if (permsRes.status === 'fulfilled') setPermissions(permsRes.value.data || []);
      if (policiesRes.status === 'fulfilled') {
        setPolicies((policiesRes.value.data || []).map(normalizeAbacPolicyRow));
      }
      if (attrsRes.status === 'fulfilled') {
        setAttributes((attrsRes.value.data || []).map(normalizeAttributeDefinitionRow));
      }
      if (wmConfigsRes.status === 'fulfilled') {
        hydrateConfigs(wmConfigsRes.value.data || []);
      }

      const dashboardData = dashboardRes.status === 'fulfilled' ? dashboardRes.value : null;
      if (healthRes.status === 'fulfilled') {
        setHealthData(mapHealthReadyResponse(healthRes.value, dashboardData));
      } else {
        const err = healthRes.reason;
        if (
          err instanceof ApiError &&
          err.response &&
          typeof err.response === 'object' &&
          ('checks' in err.response || 'status' in err.response)
        ) {
          setHealthData(
            mapHealthReadyResponse(err.response as unknown as HealthReadyResponse, dashboardData),
          );
        } else {
          setHealthData({
            status: 'OFFLINE',
            database: { status: 'OFFLINE' },
            cache: { status: 'OFFLINE' },
            uptimeSeconds: dashboardData?.process?.uptimeSeconds ?? 0,
          });
        }
      }

      if (!options?.silent) {
        setIsLoading(false);
      }
    },
    [hydrateConfigs],
  );

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
  }, [refresh, refreshTrigger]);

  async function changeUserStatus(targetUser: UserRow, action: UserStatusAction) {
    const previousUsers = users;
    setErrorMessage(null);
    setUsers((prev) => applyOptimisticUserStatus(prev, targetUser.id, action));
    setMessage(`Đã cập nhật trạng thái tài khoản ${targetUser.username}.`);

    try {
      await apiClient(`/users/${targetUser.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: targetUser.version }),
      });
      void refresh({ silent: true });
    } catch (err) {
      setUsers(previousUsers);
      setMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể cập nhật tài khoản.'
          : 'Đã xảy ra lỗi khi cập nhật tài khoản.',
      );
    }
  }

  async function disableRole(role: RoleRow) {
    if (role.isSystemRole) {
      setErrorMessage('Không thể vô hiệu hóa vai trò mặc định của hệ thống.');
      return;
    }
    const previousRoles = roles;
    setErrorMessage(null);
    setRoles((prev) => applyOptimisticRoleDisable(prev, role.id));
    setMessage(`Đã vô hiệu hóa vai trò ${role.name}.`);

    try {
      await apiClient(`/rbac/roles/${role.id}/disable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      void refresh({ silent: true });
    } catch (err) {
      setRoles(previousRoles);
      setMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể vô hiệu hóa vai trò.'
          : 'Đã xảy ra lỗi khi vô hiệu hóa vai trò.',
      );
    }
  }

  async function activatePolicy(policyId: string) {
    setErrorMessage(null);
    if (!/^\d+$/u.test(policyId)) {
      setErrorMessage('Quy tắc nháp cục bộ chưa được đồng bộ lên máy chủ PDP.');
      return;
    }
    const previousPolicies = policies;
    setPolicies((prev) => applyOptimisticPolicyActivate(prev, policyId));
    setMessage('Đã kích hoạt chính sách ABAC thành công.');

    try {
      await apiClient(`/abac/policies/${policyId}/activate`, { method: 'POST' });
      void refresh({ silent: true });
    } catch (err) {
      setPolicies(previousPolicies);
      setMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt chính sách.'
          : 'Đã xảy ra lỗi khi kích hoạt chính sách.',
      );
    }
  }

  async function saveDraftPolicy(savedRule: VisualPolicyRule) {
    setErrorMessage(null);
    const payload = {
      code: savedRule.code,
      name: savedRule.name,
      description: savedRule.description,
      effect: savedRule.effect,
      priority: savedRule.priority,
      targetResource: 'DOCUMENT' as const,
      targetAction: savedRule.targetAction,
      obligations: savedRule.obligations,
      groups: savedRule.groups,
    };

    const isExistingDbPolicy =
      /^\d+$/u.test(savedRule.id) && policies.some((p) => p.id === savedRule.id);
    const previousPolicies = policies;
    const optimisticRow: AbacPolicyRow = {
      id: savedRule.id,
      code: savedRule.code,
      name: savedRule.name,
      description: savedRule.description,
      effect: savedRule.effect,
      priority: savedRule.priority,
      targetAction: savedRule.targetAction,
      isActive: isExistingDbPolicy
        ? (policies.find((p) => p.id === savedRule.id)?.isActive ?? false)
        : false,
      obligations: savedRule.obligations,
      groups: savedRule.groups,
    };

    setPolicies((prev) =>
      isExistingDbPolicy
        ? prev.map((p) => (p.id === savedRule.id ? { ...p, ...optimisticRow } : p))
        : [optimisticRow, ...prev],
    );
    setMessage(
      isExistingDbPolicy
        ? `Đã cập nhật chính sách ABAC [${savedRule.code}] lên máy chủ PDP.`
        : `Đã tạo mới chính sách ABAC [${savedRule.code}] trên máy chủ PDP.`,
    );

    try {
      if (isExistingDbPolicy) {
        await apiClient(`/abac/policies/${savedRule.id}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
      } else {
        await apiClient('/abac/policies', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
      }
      void refresh({ silent: true });
    } catch (err) {
      setPolicies(previousPolicies);
      setMessage(null);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu chính sách ABAC lên máy chủ.'
          : 'Đã xảy ra lỗi khi lưu chính sách ABAC.',
      );
    }
  }

  return {
    users,
    departments,
    roles,
    permissions,
    policies,
    attributes,
    healthData,
    watermark: wm,
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
  };
}
