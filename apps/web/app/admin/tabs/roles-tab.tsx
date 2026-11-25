'use client';

import { useState } from 'react';
import { Ban, Edit2, Plus, RotateCcw, Settings2, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { resolvePermissionLabel } from '@/lib/permission-labels';
import { formatActiveBooleanLabel } from '@/lib/ui-labels';
import type { RoleRow } from '../types';

interface RolesTabProps {
  roles: RoleRow[];
  currentUserRoles?: readonly string[] | undefined;
  onOpenCreateRole: () => void;
  onOpenRolePermissions: (role: RoleRow) => void;
  onOpenEditRole: (role: RoleRow) => void;
  onDisableRole: (role: RoleRow) => Promise<boolean>;
  onEnableRole: (role: RoleRow) => Promise<boolean>;
  onDeleteRole: (role: RoleRow) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Ma Trận Thẻ Vai Trò & Vòng Đời Vai Trò RBAC Có Lọc Quyền Tự Sửa (`RolesTab`)
 * Mục đích: Ẩn thao tác phân quyền trên chính vai trò quản trị viên đang nắm giữ để tuân thủ chống tự nâng quyền, đồng thời hỗ trợ vô hiệu hóa, kích hoạt lại và xóa vai trò tùy chỉnh có xác nhận.
 */
export function RolesTab({
  roles,
  currentUserRoles,
  onOpenCreateRole,
  onOpenRolePermissions,
  onOpenEditRole,
  onDisableRole,
  onEnableRole,
  onDeleteRole,
  onClearError,
}: RolesTabProps) {
  const [pendingAction, setPendingAction] = useState<{
    role: RoleRow;
    action: 'disable' | 'enable' | 'delete';
  } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  return (
    <div className="space-y-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm sm:text-base font-semibold text-[#222222]">
          Vai trò và quyền hạn ({roles.length})
        </h3>
        <InteractiveHoverButton
          variant="primary"
          size="sm"
          text="Tạo vai trò mới"
          icon={<Plus size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onOpenCreateRole}
          className="shrink-0"
        />
      </div>

      <div className="grid gap-3.5 md:grid-cols-2 lg:grid-cols-3">
        {roles.map((role) => {
          const isHeldByCurrentUser = Boolean(currentUserRoles?.includes(role.code));
          return (
            <Card key={role.id} className="flex flex-col justify-between min-w-0">
              <CardHeader className="pb-2.5">
                <div className="flex items-center justify-between gap-2 min-w-0">
                  <CardTitle className="text-sm font-semibold text-[#222222] truncate">
                    {role.name}
                  </CardTitle>
                  <div className="flex items-center gap-2 shrink-0">
                    {role.isSystemRole && <Badge variant="secondary">Hệ thống</Badge>}
                    <Badge variant={role.isActive ? 'success' : 'destructive'}>
                      {formatActiveBooleanLabel(role.isActive)}
                    </Badge>
                  </div>
                </div>
                <CardDescription className="font-bold text-xs text-[#008A05]">
                  {role.code}
                </CardDescription>
                {role.description && (
                  <p className="text-xs text-[#717171] line-clamp-1 mt-0.5">{role.description}</p>
                )}
              </CardHeader>
              <CardContent className="pt-0 space-y-2.5">
                <div className="text-xs font-medium text-[#717171]">
                  Quyền hạn ({role.permissions.length})
                </div>
                <div className="flex flex-wrap gap-x-3 gap-y-1.5 max-h-24 overflow-y-auto pr-1">
                  {role.permissions.map((p, idx) => (
                    <span
                      key={p.id ?? `${p.code}-${idx}`}
                      title={p.code}
                      className="staff-badge inline-flex items-center gap-1.5 font-medium text-xs text-[#008489] min-w-0"
                    >
                      <span className="dot dot-info shrink-0" aria-hidden="true" />
                      <span className="break-words">{resolvePermissionLabel(p)}</span>
                    </span>
                  ))}
                </div>

                <div className="flex flex-wrap items-center justify-end gap-1.5 pt-2 border-t border-[#ebebeb]">
                  {isHeldByCurrentUser ? (
                    <span className="text-[11px] text-[#717171] italic mr-auto">
                      Vai trò hiện tại của bạn (không thể tự chỉnh sửa)
                    </span>
                  ) : (
                    <InteractiveHoverButton
                      variant="secondary"
                      size="sm"
                      text="Phân quyền"
                      icon={<Settings2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onOpenRolePermissions(role)}
                    />
                  )}
                  {!role.isSystemRole && !isHeldByCurrentUser && (
                    <>
                      <InteractiveHoverButton
                        variant="ghost"
                        size="sm"
                        text="Sửa"
                        icon={<Edit2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => onOpenEditRole(role)}
                      />
                      {role.isActive ? (
                        <InteractiveHoverButton
                          variant="danger"
                          size="sm"
                          text="Vô hiệu hóa"
                          icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => {
                            onClearError();
                            setPendingAction({ role, action: 'disable' });
                          }}
                        />
                      ) : (
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Kích hoạt lại"
                          icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => {
                            onClearError();
                            setPendingAction({ role, action: 'enable' });
                          }}
                        />
                      )}
                      <InteractiveHoverButton
                        variant="ghost"
                        size="sm"
                        text="Xóa"
                        icon={
                          <Trash2
                            size={16}
                            strokeWidth={1.75}
                            className="text-[#C13515]"
                            aria-hidden="true"
                          />
                        }
                        onClick={() => {
                          onClearError();
                          setPendingAction({ role, action: 'delete' });
                        }}
                      />
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <ConfirmDialog
        open={Boolean(pendingAction)}
        onOpenChange={(open) => {
          if (!open && !isSubmitting) setPendingAction(null);
        }}
        title={
          pendingAction?.action === 'delete'
            ? 'Xác nhận xóa vai trò tùy chỉnh'
            : pendingAction?.action === 'enable'
              ? 'Xác nhận kích hoạt lại vai trò'
              : 'Xác nhận vô hiệu hóa vai trò'
        }
        description={
          pendingAction?.action === 'delete'
            ? `Vai trò "${pendingAction.role.name}" (${pendingAction.role.code}) sẽ bị xóa vĩnh viễn. Nếu vai trò từng được gán cho tài khoản trước đây, hệ thống sẽ giữ lại lịch sử và yêu cầu dùng chức năng Vô hiệu hóa.`
            : pendingAction?.action === 'enable'
              ? `Vai trò "${pendingAction.role.name}" (${pendingAction.role.code}) sẽ hoạt động trở lại và có thể gán cho tài khoản.`
              : `Vai trò "${pendingAction?.role.name ?? ''}" (${pendingAction?.role.code ?? ''}) sẽ ngừng cấp quyền cho mọi tài khoản đang được gán.`
        }
        confirmLabel={
          pendingAction?.action === 'delete'
            ? 'Xác nhận xóa'
            : pendingAction?.action === 'enable'
              ? 'Kích hoạt lại'
              : 'Xác nhận vô hiệu hóa'
        }
        variant={pendingAction?.action === 'enable' ? 'primary' : 'danger'}
        isLoading={isSubmitting}
        onConfirm={async () => {
          if (!pendingAction) return;
          setIsSubmitting(true);
          try {
            const ok =
              pendingAction.action === 'delete'
                ? await onDeleteRole(pendingAction.role)
                : pendingAction.action === 'enable'
                  ? await onEnableRole(pendingAction.role)
                  : await onDisableRole(pendingAction.role);
            if (ok) setPendingAction(null);
          } finally {
            setIsSubmitting(false);
          }
        }}
      />
    </div>
  );
}
