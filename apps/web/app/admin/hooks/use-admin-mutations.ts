'use client';

import type { Dispatch, SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  applyOptimisticPolicyActivate,
  applyOptimisticRoleDisable,
  applyOptimisticUserStatus,
} from '@/lib/optimistic-state';
import { formatServiceHealthLabel } from '@/lib/ui-labels';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { normalizeAbacPolicyRow } from '../helpers';
import type {
  AbacPolicyApiDto,
  AbacPolicyRow,
  HealthStatusLabel,
  RoleRow,
  SystemHealthData,
  UserRow,
  UserStatusAction,
} from '../types';

interface UseAdminMutationsParams {
  setUsers: Dispatch<SetStateAction<UserRow[]>>;
  setRoles: Dispatch<SetStateAction<RoleRow[]>>;
  policies: AbacPolicyRow[];
  setPolicies: Dispatch<SetStateAction<AbacPolicyRow[]>>;
  healthData: SystemHealthData | null;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

function mapSnapshotStatus(status: HealthStatusLabel | undefined): 'HEALTHY' | 'DEGRADED' | 'DOWN' {
  if (status === 'ONLINE') return 'HEALTHY';
  if (status === 'DEGRADED') return 'DEGRADED';
  return 'DOWN';
}

/**
 * Thuật toán: Giao Tác Ghi Quản Trị Cập Nhật State Trực Tiếp & Optimistic UI Có Hoàn Tác Nguyên Tử (`useAdminMutations`)
 * Mục đích:
 *   - Loại bỏ hoàn toàn vòng gọi lại 10 API sau mỗi thao tác ghi ở `/admin`.
 *   - Áp dụng Optimistic UI `< 16ms` cho thao tác khóa/mở/vô hiệu tài khoản, vô hiệu vai trò và kích hoạt chính sách ABAC kèm hoàn tác bản ghi nguyên vẹn nếu máy chủ từ chối (`400`/`403`/`409`/`500`).
 *   - Cập nhật trực tiếp bảng chính sách ABAC từ phản hồi chuẩn hóa của `POST`/`PUT /abac/policies`.
 */
export function useAdminMutations({
  setUsers,
  setRoles,
  policies,
  setPolicies,
  healthData,
  setMessage,
  setErrorMessage,
}: UseAdminMutationsParams) {
  async function changeUserStatus(targetUser: UserRow, action: UserStatusAction): Promise<boolean> {
    setErrorMessage(null);
    setUsers((prev) => applyOptimisticUserStatus(prev, targetUser.id, action));
    try {
      await apiClient(`/users/${targetUser.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: targetUser.version }),
      });
      setMessage(
        action === 'unlock' && targetUser.status === 'DISABLED'
          ? `Đã kích hoạt lại tài khoản @${targetUser.username} thành công.`
          : `Đã cập nhật trạng thái tài khoản @${targetUser.username} thành công.`,
      );
      return true;
    } catch (err) {
      setUsers((prev) => prev.map((user) => (user.id === targetUser.id ? targetUser : user)));
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể cập nhật trạng thái tài khoản.'
          : 'Đã xảy ra lỗi khi cập nhật trạng thái tài khoản.',
      );
      return false;
    }
  }

  async function disableRole(role: RoleRow): Promise<boolean> {
    if (role.isSystemRole) {
      setErrorMessage('Không thể vô hiệu hóa vai trò mặc định của hệ thống.');
      return false;
    }
    setErrorMessage(null);
    setRoles((prev) => applyOptimisticRoleDisable(prev, role.id));
    try {
      await apiClient(`/rbac/roles/${role.id}/disable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      setMessage(`Đã vô hiệu hóa vai trò "${role.name}" thành công.`);
      return true;
    } catch (err) {
      setRoles((prev) => prev.map((item) => (item.id === role.id ? role : item)));
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể vô hiệu hóa vai trò.'
          : 'Đã xảy ra lỗi khi vô hiệu hóa vai trò.',
      );
      return false;
    }
  }

  async function activatePolicy(policyId: string): Promise<boolean> {
    setErrorMessage(null);
    if (!/^\d+$/u.test(policyId)) {
      setErrorMessage('Quy tắc nháp chưa được lưu trên hệ thống.');
      return false;
    }
    const previousPolicy = policies.find((item) => item.id === policyId);
    setPolicies((prev) => applyOptimisticPolicyActivate(prev, policyId));
    try {
      await apiClient(`/abac/policies/${policyId}/activate`, { method: 'POST' });
      setMessage('Đã kích hoạt chính sách truy cập thành công.');
      return true;
    } catch (err) {
      if (previousPolicy) {
        setPolicies((prev) => prev.map((item) => (item.id === policyId ? previousPolicy : item)));
      }
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt chính sách.'
          : 'Đã xảy ra lỗi khi kích hoạt chính sách.',
      );
      return false;
    }
  }

  async function saveDraftPolicy(savedRule: VisualPolicyRule): Promise<boolean> {
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

    try {
      const savedDto = isExistingDbPolicy
        ? await apiClient<AbacPolicyApiDto>(`/abac/policies/${savedRule.id}`, {
            method: 'PUT',
            body: JSON.stringify(payload),
          })
        : await apiClient<AbacPolicyApiDto>('/abac/policies', {
            method: 'POST',
            body: JSON.stringify(payload),
          });

      const normalized = normalizeAbacPolicyRow(savedDto);
      setPolicies((prev) =>
        isExistingDbPolicy
          ? prev.map((item) => (item.id === normalized.id ? normalized : item))
          : [normalized, ...prev.filter((item) => item.id !== normalized.id)],
      );

      setMessage(
        isExistingDbPolicy
          ? `Đã cập nhật chính sách truy cập [${savedRule.code}] thành công.`
          : `Đã tạo mới chính sách truy cập [${savedRule.code}] thành công.`,
      );
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu chính sách truy cập.'
          : 'Đã xảy ra lỗi khi lưu chính sách truy cập.',
      );
      return false;
    }
  }

  async function captureHealthSnapshot(): Promise<boolean> {
    setErrorMessage(null);
    const status = mapSnapshotStatus(healthData?.status);
    try {
      await apiClient('/health/snapshots', {
        method: 'POST',
        body: JSON.stringify({
          serviceName: 'api-gateway',
          status,
          details: {
            databaseStatus: healthData?.database.status ?? 'OFFLINE',
            databaseLatencyMs: healthData?.database.latencyMs ?? null,
            redisStatus: healthData?.cache.status ?? 'OFFLINE',
            storageStatus: healthData?.storage.status ?? 'OFFLINE',
            storageLatencyMs: healthData?.storage.latencyMs ?? null,
            uptimeSeconds: healthData?.uptimeSeconds ?? 0,
            memory: healthData?.memory ?? null,
          },
        }),
      });
      setMessage(
        `Đã lưu bản ghi tình trạng hệ thống (${formatServiceHealthLabel(status)}) thành công.`,
      );
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu bản ghi tình trạng hệ thống.'
          : 'Đã xảy ra lỗi khi lưu bản ghi tình trạng hệ thống.',
      );
      return false;
    }
  }

  return {
    changeUserStatus,
    disableRole,
    activatePolicy,
    saveDraftPolicy,
    captureHealthSnapshot,
  };
}
