'use client';

import type { Dispatch, SetStateAction } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  applyOptimisticDepartmentActive,
  applyOptimisticPolicyActive,
  applyOptimisticRoleEnable,
  removeOptimisticById,
} from '@/lib/optimistic-state';
import type { AbacPolicyRow, DepartmentRow, RoleRow } from '../types';

interface UseAdminLifecycleMutationsParams {
  setDepartments: Dispatch<SetStateAction<DepartmentRow[]>>;
  setRoles: Dispatch<SetStateAction<RoleRow[]>>;
  policies: AbacPolicyRow[];
  setPolicies: Dispatch<SetStateAction<AbacPolicyRow[]>>;
  setMessage: (msg: string | null) => void;
  setErrorMessage: (msg: string | null) => void;
}

/**
 * Thuật toán: Giao Tác Vòng Đời Phòng Ban, Vai Trò & Chính Sách ABAC Lạc Quan Kèm Hoàn Tác Nguyên Tử (`useAdminLifecycleMutations`)
 * Mục đích: Bổ sung các thao tác ngưng/kích hoạt lại phòng ban, kích hoạt lại/xóa vai trò tùy chỉnh và tạm tắt/xóa chính sách ABAC với hoàn tác nguyên vẹn khi máy chủ từ chối.
 */
export function useAdminLifecycleMutations({
  setDepartments,
  setRoles,
  policies,
  setPolicies,
  setMessage,
  setErrorMessage,
}: UseAdminLifecycleMutationsParams) {
  async function deactivateDepartment(dept: DepartmentRow): Promise<boolean> {
    setErrorMessage(null);
    setDepartments((prev) => applyOptimisticDepartmentActive(prev, dept.id, false));
    try {
      await apiClient(`/departments/${dept.id}/deactivate`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: dept.version }),
      });
      setMessage(`Đã ngừng hoạt động phòng ban "${dept.name}" thành công.`);
      return true;
    } catch (err) {
      setDepartments((prev) => prev.map((item) => (item.id === dept.id ? dept : item)));
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể ngừng hoạt động phòng ban.'
          : 'Đã xảy ra lỗi khi ngừng hoạt động phòng ban.',
      );
      return false;
    }
  }

  async function activateDepartment(dept: DepartmentRow): Promise<boolean> {
    setErrorMessage(null);
    setDepartments((prev) => applyOptimisticDepartmentActive(prev, dept.id, true));
    try {
      await apiClient(`/departments/${dept.id}/activate`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: dept.version }),
      });
      setMessage(`Đã kích hoạt lại phòng ban "${dept.name}" thành công.`);
      return true;
    } catch (err) {
      setDepartments((prev) => prev.map((item) => (item.id === dept.id ? dept : item)));
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt lại phòng ban.'
          : 'Đã xảy ra lỗi khi kích hoạt lại phòng ban.',
      );
      return false;
    }
  }

  async function enableRole(role: RoleRow): Promise<boolean> {
    if (role.isSystemRole) {
      setErrorMessage('Không thể thay đổi trạng thái vai trò mặc định của hệ thống.');
      return false;
    }
    setErrorMessage(null);
    setRoles((prev) => applyOptimisticRoleEnable(prev, role.id));
    try {
      await apiClient(`/rbac/roles/${role.id}/enable`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: role.version }),
      });
      setMessage(`Đã kích hoạt lại vai trò "${role.name}" thành công.`);
      return true;
    } catch (err) {
      setRoles((prev) => prev.map((item) => (item.id === role.id ? role : item)));
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể kích hoạt lại vai trò.'
          : 'Đã xảy ra lỗi khi kích hoạt lại vai trò.',
      );
      return false;
    }
  }

  async function deleteRole(role: RoleRow): Promise<boolean> {
    if (role.isSystemRole) {
      setErrorMessage('Không thể xóa vai trò mặc định của hệ thống.');
      return false;
    }
    setErrorMessage(null);
    let snapshot: RoleRow[] = [];
    setRoles((prev) => {
      snapshot = prev;
      return removeOptimisticById(prev, role.id);
    });
    try {
      await apiClient(`/rbac/roles/${role.id}`, { method: 'DELETE' });
      setMessage(`Đã xóa vai trò "${role.name}" thành công.`);
      return true;
    } catch (err) {
      setRoles(snapshot);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể xóa vai trò.'
          : 'Đã xảy ra lỗi khi xóa vai trò.',
      );
      return false;
    }
  }

  async function deactivatePolicy(policyId: string): Promise<boolean> {
    setErrorMessage(null);
    if (!/^\d+$/u.test(policyId)) {
      setErrorMessage('Quy tắc nháp chưa được lưu trên hệ thống.');
      return false;
    }
    const previousPolicy = policies.find((item) => item.id === policyId);
    setPolicies((prev) => applyOptimisticPolicyActive(prev, policyId, false));
    try {
      await apiClient(`/abac/policies/${policyId}/deactivate`, { method: 'POST' });
      setMessage('Đã tạm tắt chính sách truy cập thành công.');
      return true;
    } catch (err) {
      if (previousPolicy) {
        setPolicies((prev) => prev.map((item) => (item.id === policyId ? previousPolicy : item)));
      }
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể tạm tắt chính sách truy cập.'
          : 'Đã xảy ra lỗi khi tạm tắt chính sách truy cập.',
      );
      return false;
    }
  }

  async function deletePolicy(policy: AbacPolicyRow): Promise<boolean> {
    setErrorMessage(null);
    if (!/^\d+$/u.test(policy.id)) {
      setPolicies((prev) => removeOptimisticById(prev, policy.id));
      return true;
    }
    const snapshot = policies;
    setPolicies((prev) => removeOptimisticById(prev, policy.id));
    try {
      await apiClient(`/abac/policies/${policy.id}`, { method: 'DELETE' });
      setMessage(`Đã xóa chính sách truy cập "${policy.name}" thành công.`);
      return true;
    } catch (err) {
      setPolicies(snapshot);
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể xóa chính sách truy cập.'
          : 'Đã xảy ra lỗi khi xóa chính sách truy cập.',
      );
      return false;
    }
  }

  return {
    deactivateDepartment,
    activateDepartment,
    enableRole,
    deleteRole,
    deactivatePolicy,
    deletePolicy,
  };
}
