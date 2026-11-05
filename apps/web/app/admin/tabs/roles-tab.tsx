'use client';

import { Ban, Edit2, Plus, Settings2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { RoleRow } from '../types';

interface RolesTabProps {
  roles: RoleRow[];
  onOpenCreateRole: () => void;
  onOpenRolePermissions: (role: RoleRow) => void;
  onOpenEditRole: (role: RoleRow) => void;
  onDisableRole: (role: RoleRow) => void;
}

export function RolesTab({
  roles,
  onOpenCreateRole,
  onOpenRolePermissions,
  onOpenEditRole,
  onDisableRole,
}: RolesTabProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-[#222222]">
            Quản trị Vai trò &amp; Quyền hạn (RBAC)
          </h3>
          <p className="text-xs text-[#717171]">
            Thiết lập vai trò, ma trận phân quyền và liên kết người dùng
          </p>
        </div>
        <InteractiveHoverButton
          variant="primary"
          size="sm"
          text="Tạo vai trò mới"
          icon={<Plus size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onOpenCreateRole}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {roles.map((role) => (
          <Card
            key={role.id}
            className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col justify-between"
          >
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold text-[#222222]">{role.name}</CardTitle>
                <div className="flex items-center gap-2">
                  {role.isSystemRole && (
                    <Badge variant="secondary" className="text-[13px]">
                      Hệ thống
                    </Badge>
                  )}
                  <Badge
                    variant={role.isActive ? 'success' : 'destructive'}
                    className="text-[13px]"
                  >
                    {role.isActive ? 'Active' : 'Disabled'}
                  </Badge>
                </div>
              </div>
              <CardDescription className="font-bold text-xs text-[#008A05]">
                {role.code}
              </CardDescription>
              {role.description && (
                <p className="text-xs text-[#717171] line-clamp-2 mt-1">{role.description}</p>
              )}
            </CardHeader>
            <CardContent className="pt-0 space-y-3">
              <div className="text-xs font-medium text-[#717171]">
                Quyền hạn ({role.permissions.length}):
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 max-h-24 overflow-y-auto pr-1">
                {role.permissions.map((p, idx) => (
                  // CONFLICT-RESOLVED: Phẳng hóa nhãn quyền RBAC theo chuẩn staff-001 (không bọc nền #f7f7f7 / viền #ebebeb) tại rules/ui-design-system.md.
                  <span
                    key={idx}
                    className="staff-badge inline-flex items-center gap-1 font-mono text-[13px] text-[#008489]"
                  >
                    <span className="dot dot-info" aria-hidden="true" />
                    <span>{p.code}</span>
                  </span>
                ))}
              </div>

              <div className="flex items-center justify-end gap-1.5 pt-2 border-t border-[#ebebeb]">
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
                        onClick={() => onDisableRole(role)}
                      />
                    )}
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
