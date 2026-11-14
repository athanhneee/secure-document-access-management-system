'use client';

import type { Dispatch, SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  applyOptimisticPolicyActivate,
  applyOptimisticRoleDisable,
  applyOptimisticUserStatus,
} from '@/lib/optimistic-state';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import type { AbacPolicyRow, RoleRow, UserRow, UserStatusAction } from '../types';

interface UseAdminMutationsParams {
  users: UserRow[];
  setUsers: Dispatch<SetStateAction<UserRow[]>>;
  roles: RoleRow[];
  setRoles: Dispatch<SetStateAction<RoleRow[]>>;
  policies: AbacPolicyRow[];
  setPolicies: Dispatch<SetStateAction<AbacPolicyRow[]>>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
  refresh: (options?: { silent?: boolean }) => Promise<void>;
}

/**
 * Thuật toán: Cập Nhật Lạc Quan Trạng Thái Quản Trị Kèm Kiểm Soát Phiên Bản OCC (`useAdminMutations`)
 * Mục đích: Phản hồi tức thì `< 16ms` khi khóa/mở/vô hiệu tài khoản, vô hiệu vai trò hoặc lưu/kích hoạt chính sách ABAC, tự động hoàn trả trạng thái trước đó nếu máy chủ từ chối.
 */
export function useAdminMutations({
  users,
  setUsers,
  roles,
  setRoles,
  policies,
  setPolicies,
  setMessage,
  setErrorMessage,
  refresh,
}: UseAdminMutationsParams) {
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
    changeUserStatus,
    disableRole,
    activatePolicy,
    saveDraftPolicy,
  };
}
