'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { mapHealthReadyResponse, upsertDraftPolicy } from '../helpers';
import type {
  AbacPolicyRow,
  AttributeDefinitionRow,
  DepartmentRow,
  HealthReadyResponse,
  PermissionRow,
  RoleRow,
  SystemHealthData,
  UserRow,
  UserStatusAction,
  WatermarkConfigRow,
} from '../types';

/**
 * Thuật toán: Đồng bộ Song song Chịu lỗi Đa Phân hệ Quản trị & Kiểm soát Đồng thời Lạc quan (`useAdminData`)
 * Mục đích: Tải đồng thời 8 nguồn dữ liệu quản trị độc lập và thực thi thay đổi trạng thái an toàn chống ghi đè mất dữ liệu (lost update).
 * Cơ chế hoạt động:
 *   - Sử dụng `Promise.allSettled` gom kết quả từ 8 điểm cuối để sự cố cục bộ ở một phân hệ không làm tê liệt bảng điều khiển; gửi kèm phiên bản `expectedVersion` (Optimistic Concurrency Control) khi khóa/kích hoạt tài khoản hoặc vô hiệu hóa vai trò.
 */
export function useAdminData() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [policies, setPolicies] = useState<AbacPolicyRow[]>([]);
  const [attributes, setAttributes] = useState<AttributeDefinitionRow[]>([]);
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);

  const [watermarkConfigs, setWatermarkConfigs] = useState<WatermarkConfigRow[]>([]);
  const [activeWmConfigId, setActiveWmConfigId] = useState<string | null>(null);
  const [wmShowQr, setWmShowQr] = useState(true);
  const [wmOpacity, setWmOpacity] = useState(25);
  const [wmFontSize, setWmFontSize] = useState(14);
  const [isSavingWatermark, setIsSavingWatermark] = useState(false);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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
        apiClient<HealthReadyResponse>('/health/ready'),
      ]);

    if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data || []);
    if (deptsRes.status === 'fulfilled') setDepartments(deptsRes.value.data || []);
    if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value.data || []);
    if (permsRes.status === 'fulfilled') setPermissions(permsRes.value.data || []);
    if (policiesRes.status === 'fulfilled') setPolicies(policiesRes.value.data || []);
    if (attrsRes.status === 'fulfilled') setAttributes(attrsRes.value.data || []);
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
      setHealthData(mapHealthReadyResponse(healthRes.value));
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

  async function changeUserStatus(targetUser: UserRow, action: UserStatusAction) {
    try {
      await apiClient(`/users/${targetUser.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: targetUser.version }),
      });
      setMessage(`Đã cập nhật trạng thái tài khoản ${targetUser.username}.`);
      await refresh();
    } catch (err) {
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
    setErrorMessage(null);
    try {
      await apiClient(`/rbac/roles/${role.id}/disable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      setMessage(`Đã vô hiệu hóa vai trò ${role.name}.`);
      await refresh();
    } catch (err) {
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
    try {
      await apiClient(`/abac/policies/${policyId}/activate`, { method: 'POST' });
      setMessage('Đã kích hoạt chính sách ABAC thành công.');
      await refresh();
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt chính sách.'
          : 'Đã xảy ra lỗi khi kích hoạt chính sách.',
      );
    }
  }

  function saveDraftPolicy(savedRule: VisualPolicyRule) {
    setMessage(
      `Đã lưu bản nháp mô phỏng cục bộ [${savedRule.code}] (Nháp mô phỏng cục bộ — chưa kích hoạt trên PDP).`,
    );
    setPolicies((prev) => upsertDraftPolicy(prev, savedRule));
  }

  function selectWatermarkConfig(configId: string) {
    const found = watermarkConfigs.find((c) => c.id === configId);
    if (found) {
      setActiveWmConfigId(found.id);
      setWmOpacity(found.opacityPercent);
      setWmFontSize(found.fontSize);
      setWmShowQr(found.includeQrCode);
    }
  }

  async function saveWatermarkConfig() {
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
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu cấu hình Watermark.'
          : 'Đã xảy ra lỗi khi lưu cấu hình watermark.',
      );
    } finally {
      setIsSavingWatermark(false);
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
    watermark: {
      configs: watermarkConfigs,
      activeConfigId: activeWmConfigId,
      showQr: wmShowQr,
      setShowQr: setWmShowQr,
      opacity: wmOpacity,
      setOpacity: setWmOpacity,
      fontSize: wmFontSize,
      setFontSize: setWmFontSize,
      isSaving: isSavingWatermark,
      selectConfig: selectWatermarkConfig,
      saveConfig: saveWatermarkConfig,
    },
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
