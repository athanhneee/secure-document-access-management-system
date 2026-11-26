'use client';

import { useState } from 'react';
import type {
  AdminTab,
  ClearanceOptionRow,
  DepartmentRow,
  PermissionRow,
  RoleRow,
  UserRow,
} from '../types';
import { AssignRoleModal } from './assign-role-modal';
import { CreateRoleModal } from './create-role-modal';
import { CreateUserModal } from './create-user-modal';
import { DepartmentModal } from './department-modal';
import { EditRoleModal } from './edit-role-modal';
import { EditUserModal } from './edit-user-modal';
import { RolePermissionsModal } from './role-permissions-modal';
import { UpdateClearanceModal } from './update-clearance-modal';

/**
 * Thuật toán: Quản Lý Vòng Đời Trạng Thái Hộp Thoại Quản Trị Kèm Xóa Lỗi Tồn Đọng (`useAdminModalState`)
 * Mục đích: Đảm bảo mỗi khi mở hoặc đóng bất kỳ hộp thoại `<dialog>` nào đều xóa sạch thông báo lỗi hộp thoại cũ.
 */
export function useAdminModalState(onClearError?: () => void) {
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [editUserOpen, setEditUserOpen] = useState(false);
  const [selectedUserForEdit, setSelectedUserForEdit] = useState<UserRow | null>(null);
  const [clearanceModalOpen, setClearanceModalOpen] = useState(false);
  const [selectedUserForClearance, setSelectedUserForClearance] = useState<UserRow | null>(null);
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
    clearanceModalOpen,
    setClearanceModalOpen,
    selectedUserForClearance,
    setSelectedUserForClearance,
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
    openUpdateClearance: (user: UserRow) => {
      onClearError?.();
      setSelectedUserForClearance(user);
      setClearanceModalOpen(true);
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
  currentUserId?: string | undefined;
  hasGlobalUserManage?: boolean | undefined;
  userManageDepartmentIds?: readonly string[] | undefined;
  departments: DepartmentRow[];
  clearanceOptions: ClearanceOptionRow[];
  roles: RoleRow[];
  permissions: PermissionRow[];
  permissionsLoaded?: boolean | undefined;
  onRetryLoadPermissions?: (() => void) | undefined;
  onClearError: () => void;
  onSuccess: (message: string, targetTab?: AdminTab) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AdminModals({
  modals,
  currentUserId,
  hasGlobalUserManage,
  userManageDepartmentIds,
  departments,
  clearanceOptions,
  roles,
  permissions,
  permissionsLoaded = false,
  onRetryLoadPermissions,
  onClearError,
  onSuccess,
  onError,
}: AdminModalsProps) {
  return (
    <>
      <CreateUserModal
        open={modals.createUserOpen}
        onOpenChange={(open) => {
          modals.setCreateUserOpen(open);
          if (!open) onClearError();
        }}
        departments={departments}
        clearanceOptions={clearanceOptions}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'users')}
        onError={onError}
      />

      <EditUserModal
        open={modals.editUserOpen}
        onOpenChange={(open) => {
          modals.setEditUserOpen(open);
          if (!open) {
            modals.setSelectedUserForEdit(null);
            onClearError();
          }
        }}
        user={modals.selectedUserForEdit}
        departments={departments}
        clearanceOptions={clearanceOptions}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'users')}
        onError={onError}
      />

      <UpdateClearanceModal
        open={modals.clearanceModalOpen}
        onOpenChange={(open) => {
          modals.setClearanceModalOpen(open);
          if (!open) {
            modals.setSelectedUserForClearance(null);
            onClearError();
          }
        }}
        user={modals.selectedUserForClearance}
        clearanceOptions={clearanceOptions}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'users')}
        onError={onError}
      />

      <DepartmentModal
        open={modals.departmentModalOpen}
        onOpenChange={(open) => {
          modals.setDepartmentModalOpen(open);
          if (!open) {
            modals.setSelectedDepartment(null);
            onClearError();
          }
        }}
        department={modals.selectedDepartment}
        departments={departments}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'departments')}
        onError={onError}
      />

      <CreateRoleModal
        open={modals.createRoleOpen}
        onOpenChange={(open) => {
          modals.setCreateRoleOpen(open);
          if (!open) onClearError();
        }}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'rbac')}
        onError={onError}
      />

      <EditRoleModal
        open={modals.editRoleOpen}
        onOpenChange={(open) => {
          modals.setEditRoleOpen(open);
          if (!open) {
            modals.setSelectedRoleForEdit(null);
            onClearError();
          }
        }}
        role={modals.selectedRoleForEdit}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'rbac')}
        onError={onError}
      />

      <RolePermissionsModal
        open={modals.permsModalOpen}
        onOpenChange={(open) => {
          modals.setPermsModalOpen(open);
          if (!open) {
            modals.setSelectedRoleForPerms(null);
            onClearError();
          }
        }}
        role={modals.selectedRoleForPerms}
        permissions={permissions}
        permissionsLoaded={permissionsLoaded}
        onRetryLoadPermissions={onRetryLoadPermissions}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'rbac')}
        onError={onError}
      />

      <AssignRoleModal
        open={modals.assignRoleOpen}
        onOpenChange={(open) => {
          modals.setAssignRoleOpen(open);
          if (!open) {
            modals.setSelectedUserForRole(null);
            onClearError();
          }
        }}
        targetUser={modals.selectedUserForRole}
        currentUserId={currentUserId}
        hasGlobalUserManage={hasGlobalUserManage}
        userManageDepartmentIds={userManageDepartmentIds}
        departments={departments}
        roles={roles}
        onClearError={onClearError}
        onSuccess={(msg) => onSuccess(msg, 'users')}
        onError={onError}
      />
    </>
  );
}
