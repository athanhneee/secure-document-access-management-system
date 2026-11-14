'use client';

import type { Dispatch, SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  applyOptimisticPolicyActivate,
  applyOptimisticRoleDisable,
  applyOptimisticUserStatus,
} from '@/lib/optimistic-state';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import type {
  AbacPolicyRow,
  HealthStatusLabel,
  RoleRow,
  SystemHealthData,
  UserRow,
  UserStatusAction,
} from '../types';

interface UseAdminMutationsParams {
  users: UserRow[];
  setUsers: Dispatch<SetStateAction<UserRow[]>>;
  roles: RoleRow[];
  setRoles: Dispatch<SetStateAction<RoleRow[]>>;
  policies: AbacPolicyRow[];
  setPolicies: Dispatch<SetStateAction<AbacPolicyRow[]>>;
  healthData: SystemHealthData | null;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
  refresh: (options?: { silent?: boolean }) => Promise<void>;
}

function mapSnapshotStatus(status: HealthStatusLabel | undefined): 'HEALTHY' | 'DEGRADED' | 'DOWN' {
  if (status === 'ONLINE') return 'HEALTHY';
  if (status === 'DEGRADED') return 'DEGRADED';
  return 'DOWN';
}

/**
 * Thuật toán: Giao Tác Ghi Quản Trị Xác Thực Máy Chủ Trước Khi Phản Hồi Giao Diện (`useAdminMutations`)
 * Mục đích: Mọi thao tác ghi (`POST`/`PUT`/`PATCH`) bắt buộc `await` phản hồi thành công từ máy chủ trước khi cập nhật trạng thái bảng, đóng hộp thoại hoặc hiển thị thông báo thành công.
 */
export function useAdminMutations({
  setUsers,
  setRoles,
  policies,
  setPolicies,
  healthData,
  setMessage,
  setErrorMessage,
  refresh,
}: UseAdminMutationsParams) {
  async function changeUserStatus(targetUser: UserRow, action: UserStatusAction): Promise<boolean> {
    setErrorMessage(null);
    try {
      await apiClient(`/users/${targetUser.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: targetUser.version }),
      });
      setUsers((prev) => applyOptimisticUserStatus(prev, targetUser.id, action));
      setMessage(
        action === 'unlock' && targetUser.status === 'DISABLED'
          ? `Đã kích hoạt lại tài khoản @${targetUser.username} thành công.`
          : `Đã cập nhật trạng thái tài khoản @${targetUser.username} thành công.`,
      );
      void refresh({ silent: true });
      return true;
    } catch (err) {
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
    try {
      await apiClient(`/rbac/roles/${role.id}/disable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      setRoles((prev) => applyOptimisticRoleDisable(prev, role.id));
      setMessage(`Đã vô hiệu hóa vai trò "${role.name}" thành công.`);
      void refresh({ silent: true });
      return true;
    } catch (err) {
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
      setErrorMessage('Quy tắc nháp cục bộ chưa được đồng bộ lên máy chủ PDP.');
      return false;
    }
    try {
      await apiClient(`/abac/policies/${policyId}/activate`, { method: 'POST' });
      setPolicies((prev) => applyOptimisticPolicyActivate(prev, policyId));
      setMessage('Đã kích hoạt chính sách ABAC thành công.');
      void refresh({ silent: true });
      return true;
    } catch (err) {
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

      setMessage(
        isExistingDbPolicy
          ? `Đã cập nhật chính sách ABAC [${savedRule.code}] lên máy chủ PDP.`
          : `Đã tạo mới chính sách ABAC [${savedRule.code}] trên máy chủ PDP.`,
      );
      await refresh({ silent: true });
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể lưu chính sách ABAC lên máy chủ.'
          : 'Đã xảy ra lỗi khi lưu chính sách ABAC.',
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
      setMessage(`Đã chụp và lưu bản ghi sức khỏe hệ thống (${status}) thành công.`);
      void refresh({ silent: true });
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể chụp bản ghi sức khỏe hệ thống.'
          : 'Đã xảy ra lỗi khi chụp bản ghi sức khỏe hệ thống.',
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
