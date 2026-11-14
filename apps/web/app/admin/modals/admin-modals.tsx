'use client';

import { useState } from 'react';
import type { DepartmentRow, PermissionRow, RoleRow, UserRow } from '../types';
import { AssignRoleModal } from './assign-role-modal';
import { CreateRoleModal } from './create-role-modal';
import { CreateUserModal } from './create-user-modal';
import { DepartmentModal } from './department-modal';
import { EditRoleModal } from './edit-role-modal';
import { EditUserModal } from './edit-user-modal';
import { RolePermissionsModal } from './role-permissions-modal';

/**
 * Thuật toán: Quản Lý Vòng Đời Trạng Thái Hộp Thoại Quản Trị Kèm Xóa Lỗi Tồn Đọng (`useAdminModalState`)
 * Mục đích: Đảm bảo mỗi khi mở bất kỳ hộp thoại `<dialog>` mới nào đều xóa sạch thông báo lỗi cũ từ trang hoặc hộp thoại trước đó.
 */
export function useAdminModalState(onClearError?: () => void) {
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [editUserOpen, setEditUserOpen] = useState(false);
  const [selectedUserForEdit, setSelectedUserForEdit] = useState<UserRow | null>(null);
  const [departmentModalOpen, setDepartmentModalOpen] = useState(false);
  const [selectedDepartment, setSelectedDepartment] = useState<DepartmentRow | null>(null);
  const [createRoleOpen, setCreateRoleOpen] = useState(false);
  const [editRoleOpen, setEditRoleOpen] = useState(false);
  const [selectedRoleForEdit, setSelectedRoleForEdit] = useState<RoleRow | null>(null);
  const [permsModalOpen, setPermsModalOpen] = useState(false);
  const [selectedRoleForPerms, setSelectedRoleForPerms] = useState<RoleRow | null>(null);
  const [assignRoleOpen, setAssignRoleOpen] = useState(false);
  const [selectedUserForRole, setSelectedUserForRole] = useState<UserRow | null>(null);

  return {
    createUserOpen,
    setCreateUserOpen,
    editUserOpen,
    setEditUserOpen,
    selectedUserForEdit,
    setSelectedUserForEdit,
    departmentModalOpen,
    setDepartmentModalOpen,
    selectedDepartment,
    setSelectedDepartment,
    createRoleOpen,
    setCreateRoleOpen,
    editRoleOpen,
    setEditRoleOpen,
    selectedRoleForEdit,
    setSelectedRoleForEdit,
    permsModalOpen,
    setPermsModalOpen,
    selectedRoleForPerms,
    setSelectedRoleForPerms,
    assignRoleOpen,
    setAssignRoleOpen,
    selectedUserForRole,
    setSelectedUserForRole,
    openCreateUser: () => {
      onClearError?.();
      setCreateUserOpen(true);
    },
    openEditUser: (user: UserRow) => {
      onClearError?.();
      setSelectedUserForEdit(user);
      setEditUserOpen(true);
    },
    openCreateDepartment: () => {
      onClearError?.();
      setSelectedDepartment(null);
      setDepartmentModalOpen(true);
    },
    openEditDepartment: (dept: DepartmentRow) => {
      onClearError?.();
      setSelectedDepartment(dept);
      setDepartmentModalOpen(true);
    },
    openCreateRole: () => {
      onClearError?.();
      setCreateRoleOpen(true);
    },
    openEditRole: (role: RoleRow) => {
      onClearError?.();
      setSelectedRoleForEdit(role);
      setEditRoleOpen(true);
    },
    openRolePermissions: (role: RoleRow) => {
      onClearError?.();
      setSelectedRoleForPerms(role);
      setPermsModalOpen(true);
    },
    openAssignRole: (user: UserRow) => {
      onClearError?.();
      setSelectedUserForRole(user);
      setAssignRoleOpen(true);
    },
  };
}

export type AdminModalState = ReturnType<typeof useAdminModalState>;

interface AdminModalsProps {
  modals: AdminModalState;
  departments: DepartmentRow[];
  roles: RoleRow[];
  permissions: PermissionRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AdminModals({
  modals,
  departments,
  roles,
  permissions,
  onClearError,
  onSuccess,
  onError,
}: AdminModalsProps) {
  return (
    <>
      <CreateUserModal
        open={modals.createUserOpen}
        onOpenChange={modals.setCreateUserOpen}
        departments={departments}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <EditUserModal
        open={modals.editUserOpen}
        onOpenChange={(open) => {
          modals.setEditUserOpen(open);
          if (!open) modals.setSelectedUserForEdit(null);
        }}
        user={modals.selectedUserForEdit}
        departments={departments}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <DepartmentModal
        open={modals.departmentModalOpen}
        onOpenChange={(open) => {
          modals.setDepartmentModalOpen(open);
          if (!open) modals.setSelectedDepartment(null);
        }}
        department={modals.selectedDepartment}
        departments={departments}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <CreateRoleModal
        open={modals.createRoleOpen}
        onOpenChange={modals.setCreateRoleOpen}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <EditRoleModal
        open={modals.editRoleOpen}
        onOpenChange={(open) => {
          modals.setEditRoleOpen(open);
          if (!open) modals.setSelectedRoleForEdit(null);
        }}
        role={modals.selectedRoleForEdit}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <RolePermissionsModal
        open={modals.permsModalOpen}
        onOpenChange={(open) => {
          modals.setPermsModalOpen(open);
          if (!open) modals.setSelectedRoleForPerms(null);
        }}
        role={modals.selectedRoleForPerms}
        permissions={permissions}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />

      <AssignRoleModal
        open={modals.assignRoleOpen}
        onOpenChange={(open) => {
          modals.setAssignRoleOpen(open);
          if (!open) modals.setSelectedUserForRole(null);
        }}
        targetUser={modals.selectedUserForRole}
        roles={roles}
        onClearError={onClearError}
        onSuccess={onSuccess}
        onError={onError}
      />
    </>
  );
}
