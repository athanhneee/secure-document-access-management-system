'use client';

import { useMemo, useState, type FormEvent } from 'react';
import { AlertTriangle, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { resolvePermissionLabel, resolvePermissionScopeLabel } from '@/lib/permission-labels';
import {
  isPermissionSodCompatibleWithSelection,
  resolveCompatibleSodArchetypes,
  resolvePermissionUiGroup,
  SOD_ARCHETYPE_LABELS,
  SOD_UI_GROUP_META,
  SYSTEM_ROLE_ALLOWED_CODES,
  type SodUiGroupKey,
} from '@/lib/rbac-sod';
import { resolveRolePermissionIds } from '../helpers';
import type { PermissionRow, RoleRow } from '../types';

interface RolePermissionsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: RoleRow | null;
  permissions: PermissionRow[];
  permissionsLoaded?: boolean | undefined;
  onRetryLoadPermissions?: (() => void) | undefined;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Modal Phân Quyền Nhóm Theo 4 Trụ Cột Phân Tách Nhiệm Vụ SoD, Khóa Chéo Tự Động & Khóa Cứng Khi Thiếu Danh Mục (`RolePermissionsModal`, BUG-091)
 * Mục đích:
 *   - Chặn tuyệt đối thao tác lưu khi `!permissionsLoaded || permissions.length === 0` để không bao giờ gửi `{ permissionIds: [] }` xóa trắng quyền vai trò khi `GET /rbac/permissions` gặp lỗi.
 *   - Áp dụng ma trận đặc quyền tối thiểu cho vai trò hệ thống và khóa chéo 4 trụ cột SoD cho vai trò tùy chỉnh.
 */
export function RolePermissionsModal({
  open,
  onOpenChange,
  role,
  permissions,
  permissionsLoaded = false,
  onRetryLoadPermissions,
  onClearError,
  onSuccess,
  onError,
}: RolePermissionsModalProps) {
  const [isSavingPerms, setIsSavingPerms] = useState(false);

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isSavingPerms) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isSavingPerms}
        className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Phân quyền cho vai trò: {role?.name} ({role?.code})
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            {role?.isSystemRole
              ? 'Vai trò hệ thống chỉ được chọn các quyền nằm trong khung đặc quyền tối thiểu đã phê duyệt.'
              : 'Áp dụng Phân tách nhiệm vụ (SoD): mỗi vai trò tùy chỉnh chỉ được thuộc 1 trong 4 trụ cột độc lập (Quản trị hệ thống, An ninh SOC, Kiểm toán hoặc Nghiệp vụ tài liệu).'}
          </DialogDescription>
        </DialogHeader>

        {open && role && (
          <RolePermissionsForm
            key={`${role.id}-${permissionsLoaded ? permissions.length : 'unloaded'}`}
            role={role}
            permissions={permissions}
            permissionsLoaded={permissionsLoaded}
            onRetryLoadPermissions={onRetryLoadPermissions}
            isSavingPerms={isSavingPerms}
            setIsSavingPerms={setIsSavingPerms}
            onClose={() => handleDialogOpenChange(false)}
            onClearError={onClearError}
            onSuccess={onSuccess}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

interface RolePermissionsFormProps {
  role: RoleRow;
  permissions: PermissionRow[];
  permissionsLoaded: boolean;
  onRetryLoadPermissions?: (() => void) | undefined;
  isSavingPerms: boolean;
  setIsSavingPerms: (saving: boolean) => void;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function RolePermissionsForm({
  role,
  permissions,
  permissionsLoaded,
  onRetryLoadPermissions,
  isSavingPerms,
  setIsSavingPerms,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: RolePermissionsFormProps) {
  const [selectedPermIds, setSelectedPermIds] = useState<string[]>(() =>
    resolveRolePermissionIds(role, permissions),
  );

  const catalogUnavailable = !permissionsLoaded || permissions.length === 0;
  const allowedSet = role.isSystemRole ? SYSTEM_ROLE_ALLOWED_CODES[role.code] : undefined;

  const selectedPermissions = useMemo(
    () => permissions.filter((p) => selectedPermIds.includes(p.id)),
    [permissions, selectedPermIds],
  );

  const compatibleArchetypes = useMemo(
    () => resolveCompatibleSodArchetypes(selectedPermissions),
    [selectedPermissions],
  );

  const groupedPermissions = useMemo(() => {
    const groups = new Map<SodUiGroupKey, PermissionRow[]>();
    for (const domain of SOD_UI_GROUP_META) groups.set(domain.key, []);
    for (const perm of permissions) {
      groups.get(resolvePermissionUiGroup(perm))?.push(perm);
    }
    return SOD_UI_GROUP_META.map((meta) => ({
      ...meta,
      items: groups.get(meta.key) ?? [],
    })).filter((g) => g.items.length > 0);
  }, [permissions]);

  const compatibleLabels = useMemo(
    () => [...compatibleArchetypes].map((key) => SOD_ARCHETYPE_LABELS[key]),
    [compatibleArchetypes],
  );

  async function handleSaveRolePermissions(e: FormEvent) {
    e.preventDefault();
    if (catalogUnavailable) {
      onError(
        'Danh mục quyền hạn chưa được tải thành công từ máy chủ. Đã khóa thao tác lưu để ngăn xóa nhầm quyền của vai trò.',
      );
      return;
    }
    setIsSavingPerms(true);
    onClearError();
    try {
      await apiClient(`/rbac/roles/${role.id}/permissions`, {
        method: 'PUT',
        body: JSON.stringify({ permissionIds: selectedPermIds }),
      });

      setIsSavingPerms(false);
      onOpenSafeClose();
      await onSuccess(`Đã cập nhật danh sách quyền hạn cho vai trò "${role.name}".`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể cập nhật quyền.');
      } else {
        onError('Đã xảy ra lỗi khi cập nhật quyền hạn vai trò.');
      }
      setIsSavingPerms(false);
    }
  }

  function onOpenSafeClose() {
    onClose();
  }

  return (
    <form onSubmit={handleSaveRolePermissions} noValidate className="space-y-4 py-2 text-xs">
      {catalogUnavailable && (
        <div
          role="alert"
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 text-xs text-[#222222]"
        >
          <div className="flex items-start gap-2 min-w-0">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="mt-0.5 shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <div className="space-y-0.5 leading-relaxed">
              <div className="font-semibold text-[#C13515]">
                Không thể tải danh mục quyền hạn hệ thống
              </div>
              <p className="text-[#717171]">
                Nút lưu đã được khóa an toàn để ngăn gửi danh sách rỗng làm mất toàn bộ quyền hiện
                tại của vai trò. Vui lòng tải lại danh mục trước khi chỉnh sửa.
              </p>
            </div>
          </div>
          {onRetryLoadPermissions && (
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              text="Tải lại quyền"
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={onRetryLoadPermissions}
              className="shrink-0"
            />
          )}
        </div>
      )}

      {!catalogUnavailable && !role.isSystemRole && (
        <div className="flex items-start gap-2 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] px-3 py-2 text-xs text-[#222222]">
          <ShieldAlert
            size={16}
            strokeWidth={1.75}
            className="mt-0.5 shrink-0 text-[#008489]"
            aria-hidden="true"
          />
          <div className="min-w-0 leading-relaxed">
            <span className="font-semibold text-[#222222]">
              Miền Phân tách nhiệm vụ (SoD) đang chọn:{' '}
            </span>
            {selectedPermissions.length === 0 ? (
              <span className="text-[#717171]">
                Chưa chọn quyền nào — có thể chọn 1 trong 4 trụ cột bên dưới.
              </span>
            ) : compatibleLabels.length > 0 ? (
              <span className="font-semibold text-[#008A05]">{compatibleLabels.join(' · ')}</span>
            ) : (
              <span className="font-semibold text-[#C13515]">
                Xung đột SoD — vui lòng bỏ chọn các quyền trái trụ cột trước khi lưu.
              </span>
            )}
          </div>
        </div>
      )}

      {!catalogUnavailable && (
        <div className="max-h-80 overflow-y-auto pr-1 space-y-4">
          {groupedPermissions.map((group) => (
            <div key={group.key} className="space-y-2">
              <div className="flex flex-wrap items-baseline justify-between gap-1 border-b border-[#ebebeb] pb-1">
                <span className="font-semibold text-xs text-[#222222]">{group.title}</span>
                <span className="text-[11px] text-[#717171]">{group.hint}</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {group.items.map((perm) => {
                  const isChecked = selectedPermIds.includes(perm.id);
                  const isDisallowedByMatrix = Boolean(allowedSet && !allowedSet.has(perm.code));
                  const isBlockedBySod =
                    !role.isSystemRole &&
                    !isChecked &&
                    selectedPermissions.length > 0 &&
                    !isPermissionSodCompatibleWithSelection(perm, compatibleArchetypes);
                  const isDisabled = isDisallowedByMatrix || isBlockedBySod || isSavingPerms;
                  const permLabel = resolvePermissionLabel(perm);
                  const permScopeLabel = resolvePermissionScopeLabel(perm);
                  const tooltip = isDisallowedByMatrix
                    ? `${perm.code} — Không nằm trong ma trận đặc quyền của vai trò hệ thống ${role.code}`
                    : isBlockedBySod
                      ? `${perm.code} — Bị khóa do vi phạm Phân tách nhiệm vụ (SoD) với các quyền đang chọn`
                      : perm.code;

                  return (
                    <label
                      key={perm.id}
                      htmlFor={`role-perm-${perm.id}`}
                      aria-label={permLabel}
                      title={tooltip}
                      className={`flex items-start gap-2.5 min-h-11 p-2.5 rounded-[16px] border transition-colors min-w-0 ${
                        isDisabled
                          ? 'border-[#ebebeb] bg-[#f7f7f7] opacity-55 cursor-not-allowed'
                          : isChecked
                            ? 'border-[#222222] bg-[#f7f7f7] cursor-pointer'
                            : 'border-[#ebebeb] hover:bg-[#f7f7f7] cursor-pointer'
                      }`}
                    >
                      <input
                        id={`role-perm-${perm.id}`}
                        type="checkbox"
                        checked={isChecked}
                        disabled={isDisabled}
                        onChange={(e) => {
                          if (isDisabled) return;
                          if (e.target.checked) {
                            setSelectedPermIds((prev) => Array.from(new Set([...prev, perm.id])));
                          } else {
                            setSelectedPermIds((prev) => prev.filter((id) => id !== perm.id));
                          }
                        }}
                        className="mt-0.5 h-4 w-4 shrink-0 rounded border-[#dddddd] accent-[#FF385C] disabled:opacity-50"
                      />
                      <div className="min-w-0">
                        <div className="font-semibold text-[13px] text-[#222222] leading-snug break-words">
                          {permLabel}
                        </div>
                        <div className="text-xs text-[#717171] mt-0.5 break-words">
                          {permScopeLabel}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Hủy"
          disabled={isSavingPerms}
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text="Lưu"
          icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
          disabled={
            catalogUnavailable ||
            isSavingPerms ||
            (!role.isSystemRole && compatibleArchetypes.size === 0)
          }
          isLoading={isSavingPerms}
        />
      </DialogFooter>
    </form>
  );
}
