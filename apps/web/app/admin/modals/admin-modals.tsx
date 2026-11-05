'use client';

import { useState } from 'react';
import type { DepartmentRow, PermissionRow, RoleRow, UserRow } from '../types';
import { AssignRoleModal } from './assign-role-modal';
import { CreateRoleModal } from './create-role-modal';
import { CreateUserModal } from './create-user-modal';
import { EditRoleModal } from './edit-role-modal';
import { RolePermissionsModal } from './role-permissions-modal';

export function useAdminModalState() {
  const [createUserOpen, setCreateUserOpen] = useState(false);
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
    openCreateUser: () => setCreateUserOpen(true),
    openCreateRole: () => setCreateRoleOpen(true),
    openEditRole: (role: RoleRow) => {
      setSelectedRoleForEdit(role);
      setEditRoleOpen(true);
    },
    openRolePermissions: (role: RoleRow) => {
      setSelectedRoleForPerms(role);
      setPermsModalOpen(true);
    },
    openAssignRole: (user: UserRow) => {
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
