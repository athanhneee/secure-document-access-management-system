'use client';

import { useState } from 'react';
import { Ban, Edit2, Plus, Settings2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { RoleRow } from '../types';

interface RolesTabProps {
  roles: RoleRow[];
  onOpenCreateRole: () => void;
  onOpenRolePermissions: (role: RoleRow) => void;
  onOpenEditRole: (role: RoleRow) => void;
  onDisableRole: (role: RoleRow) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Ma Trận Thẻ Vai Trò & Vô Hiệu Hóa Vai Trò RBAC Có Xác Nhận (`RolesTab`)
 */
export function RolesTab({
  roles,
  onOpenCreateRole,
  onOpenRolePermissions,
  onOpenEditRole,
  onDisableRole,
  onClearError,
}: RolesTabProps) {
  const [roleToDisable, setRoleToDisable] = useState<RoleRow | null>(null);
  const [isDisabling, setIsDisabling] = useState(false);

  return (
    <div className="space-y-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm sm:text-base font-semibold text-[#222222]">
          Vai trò &amp; Quyền hạn RBAC ({roles.length})
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
        {roles.map((role) => (
          <Card key={role.id} className="flex flex-col justify-between">
            <CardHeader className="pb-2.5">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-sm font-semibold text-[#222222] truncate">
                  {role.name}
                </CardTitle>
                <div className="flex items-center gap-2 shrink-0">
                  {role.isSystemRole && <Badge variant="secondary">Hệ thống</Badge>}
                  <Badge variant={role.isActive ? 'success' : 'destructive'}>
                    {role.isActive ? 'Active' : 'Disabled'}
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
              <div className="flex flex-wrap gap-x-2.5 gap-y-1 max-h-20 overflow-y-auto pr-1">
                {role.permissions.map((p, idx) => (
                  <span
                    key={idx}
                    className="staff-badge inline-flex items-center gap-1 font-mono text-xs text-[#008489]"
                  >
                    <span className="dot dot-info" aria-hidden="true" />
                    <span>{p.code}</span>
                  </span>
                ))}
              </div>

              <div className="flex flex-wrap items-center justify-end gap-1.5 pt-2 border-t border-[#ebebeb]">
                <InteractiveHoverButton
                  variant="secondary"
                  size="sm"
                  text="Phân quyền"
                  icon={<Settings2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={() => onOpenRolePermissions(role)}
                />
                {!role.isSystemRole && (
                  <>
                    <InteractiveHoverButton
                      variant="ghost"
                      size="sm"
                      text="Sửa"
                      icon={<Edit2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onOpenEditRole(role)}
                    />
                    {role.isActive && (
                      <InteractiveHoverButton
                        variant="danger"
                        size="sm"
                        text="Vô hiệu"
                        icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => {
                          onClearError();
                          setRoleToDisable(role);
                        }}
                      />
                    )}
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <ConfirmDialog
        open={Boolean(roleToDisable)}
        onOpenChange={(open) => {
          if (!open && !isDisabling) setRoleToDisable(null);
        }}
        title="Xác nhận vô hiệu hóa vai trò RBAC"
        description={`Vai trò "${roleToDisable?.name ?? ''}" (${roleToDisable?.code ?? ''}) sẽ ngưng cấp quyền cho mọi nhân sự đang liên kết.`}
        confirmLabel="Xác nhận vô hiệu hóa"
        variant="danger"
        isLoading={isDisabling}
        onConfirm={async () => {
          if (!roleToDisable) return;
          setIsDisabling(true);
          try {
            const ok = await onDisableRole(roleToDisable);
            if (ok) setRoleToDisable(null);
          } finally {
            setIsDisabling(false);
          }
        }}
      />
    </div>
  );
}
