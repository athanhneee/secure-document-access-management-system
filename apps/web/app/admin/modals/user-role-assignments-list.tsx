'use client';

import { useState } from 'react';
import { CalendarClock, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { UserRoleAssignmentRow } from '../types';

interface UserRoleAssignmentsListProps {
  assignments: UserRoleAssignmentRow[];
  asOfMs: number;
  isLoading: boolean;
  canRevoke: boolean;
  onRevoke: (assignment: UserRoleAssignmentRow) => Promise<boolean>;
}

function formatDateTimeVi(iso: string): string {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return iso;
  return date.toLocaleString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Thuật toán: Phân Loại Trạng Thái Hiệu Lực Thời Gian Của Bản Ghi Gán Vai Trò (`resolveAssignmentState`)
 */
function resolveAssignmentState(assignment: UserRoleAssignmentRow, nowMs: number) {
  const fromMs = Date.parse(assignment.validFrom);
  const toMs = assignment.validTo ? Date.parse(assignment.validTo) : null;
  if (toMs !== null && toMs <= nowMs) {
    return { label: 'Đã hết hạn', variant: 'secondary' as const, revocable: false };
  }
  if (fromMs > nowMs) {
    return { label: 'Hẹn giờ', variant: 'warning' as const, revocable: true };
  }
  return { label: 'Đang hiệu lực', variant: 'success' as const, revocable: true };
}

/**
 * Thuật toán: Hiển Thị & Thu Hồi Danh Sách Vai Trò Hiện Tại Của Tài Khoản (`UserRoleAssignmentsList`)
 */
export function UserRoleAssignmentsList({
  assignments,
  asOfMs,
  isLoading,
  canRevoke,
  onRevoke,
}: UserRoleAssignmentsListProps) {
  const [targetToRevoke, setTargetToRevoke] = useState<UserRoleAssignmentRow | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);

  return (
    <div className="space-y-2 pb-3 border-b border-[#ebebeb]">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold text-[#222222] inline-flex items-center gap-1.5">
          <CalendarClock
            size={16}
            strokeWidth={1.75}
            className="text-[#717171]"
            aria-hidden="true"
          />
          <span>Vai trò đã gán ({assignments.length})</span>
        </span>
      </div>

      {isLoading ? (
        <p className="text-xs text-[#717171] py-2">Đang tải danh sách vai trò hiện tại…</p>
      ) : assignments.length === 0 ? (
        <p className="text-xs text-[#717171] py-1">Tài khoản chưa được gán vai trò nào.</p>
      ) : (
        <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1">
          {assignments.map((item) => {
            const state = resolveAssignmentState(item, asOfMs);
            return (
              <div
                key={item.id}
                className="flex items-center justify-between gap-2 p-2.5 rounded-[12px] border border-[#ebebeb] bg-[#f7f7f7]"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-xs text-[#222222] truncate">
                      {item.roleName || item.roleCode}
                    </span>
                    <span className="font-mono text-[11px] text-[#717171]">{item.roleCode}</span>
                    <Badge variant={state.variant}>{state.label}</Badge>
                  </div>
                  <div className="text-[11px] text-[#717171] tabular-nums">
                    {formatDateTimeVi(item.validFrom)} →{' '}
                    {item.validTo ? formatDateTimeVi(item.validTo) : 'Không giới hạn'}
                  </div>
                </div>

                {canRevoke && state.revocable && (
                  <InteractiveHoverButton
                    type="button"
                    variant="danger"
                    size="sm"
                    text="Thu hồi"
                    icon={<Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={() => setTargetToRevoke(item)}
                    className="shrink-0"
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={Boolean(targetToRevoke)}
        onOpenChange={(open) => {
          if (!open && !isRevoking) setTargetToRevoke(null);
        }}
        title="Xác nhận thu hồi vai trò"
        description={`Thu hồi vai trò ${targetToRevoke?.roleName || targetToRevoke?.roleCode || ''} của tài khoản này ngay lập tức? Quyền truy cập liên quan sẽ mất hiệu lực ngay.`}
        confirmLabel="Xác nhận thu hồi"
        variant="danger"
        isLoading={isRevoking}
        onConfirm={async () => {
          if (!targetToRevoke) return;
          setIsRevoking(true);
          try {
            const ok = await onRevoke(targetToRevoke);
            if (ok) setTargetToRevoke(null);
          } finally {
            setIsRevoking(false);
          }
        }}
      />
    </div>
  );
}
