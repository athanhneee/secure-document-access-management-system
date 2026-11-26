'use client';

import { useState } from 'react';
import { Ban, Pencil, Plus, RotateCcw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatActiveBooleanLabel } from '@/lib/ui-labels';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { resolveParentDepartmentLabel } from '../helpers';
import type { DepartmentRow } from '../types';

interface DepartmentsTabProps {
  departments: DepartmentRow[];
  onOpenCreateDepartment: () => void;
  onOpenEditDepartment: (department: DepartmentRow) => void;
  onDeactivateDepartment: (department: DepartmentRow) => Promise<boolean>;
  onActivateDepartment: (department: DepartmentRow) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Hiển Thị & Quản Trị Cây Phân Cấp Phòng Ban Tổ Chức Kèm Ngưng/Kích Hoạt Lại Theo OCC (`DepartmentsTab`)
 * Mục đích: Ánh xạ nhãn đơn vị cấp trên từ danh sách phẳng `departments` và điều phối tạo mới, cập nhật, ngừng hoạt động hoặc kích hoạt lại phòng ban có xác nhận an toàn.
 */
export function DepartmentsTab({
  departments,
  onOpenCreateDepartment,
  onOpenEditDepartment,
  onDeactivateDepartment,
  onActivateDepartment,
  onClearError,
}: DepartmentsTabProps) {
  const [pendingAction, setPendingAction] = useState<{
    department: DepartmentRow;
    action: 'deactivate' | 'activate';
  } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  return (
    <>
      <Card>
        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Cơ cấu phòng ban ({departments.length})
          </CardTitle>
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text="Thêm phòng ban"
            icon={<Plus size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onOpenCreateDepartment}
            className="shrink-0"
          />
        </CardHeader>
        <CardContent className="p-0">
          {/* Bố cục thẻ di động tối ưu 375px */}
          <div className="md:hidden divide-y divide-[#ebebeb]">
            {departments.length === 0 ? (
              <div className="py-8 px-4 text-center text-xs text-[#717171]">
                Chưa có phòng ban nào được tạo.
              </div>
            ) : (
              departments.map((dept) => (
                <article key={dept.id} className="px-4 py-4 space-y-2.5 bg-[#ffffff]">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-[#222222]">{dept.code}</span>
                    <Badge variant={dept.isActive ? 'success' : 'secondary'}>
                      {formatActiveBooleanLabel(dept.isActive)}
                    </Badge>
                  </div>
                  <h3 className="text-sm font-semibold text-[#222222] break-words">{dept.name}</h3>
                  <p className="text-xs text-[#717171]">
                    Cấp trên:{' '}
                    <span className="font-medium text-[#222222]">
                      {resolveParentDepartmentLabel(departments, dept.parentId)}
                    </span>
                  </p>
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <InteractiveHoverButton
                      variant="secondary"
                      size="sm"
                      text="Sửa"
                      icon={<Pencil size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onOpenEditDepartment(dept)}
                      className="w-full"
                    />
                    {dept.isActive ? (
                      <InteractiveHoverButton
                        variant="danger"
                        size="sm"
                        text="Ngừng hoạt động"
                        icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => {
                          onClearError();
                          setPendingAction({ department: dept, action: 'deactivate' });
                        }}
                        className="w-full"
                      />
                    ) : (
                      <InteractiveHoverButton
                        variant="secondary"
                        size="sm"
                        text="Kích hoạt lại"
                        icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => {
                          onClearError();
                          setPendingAction({ department: dept, action: 'activate' });
                        }}
                        className="w-full"
                      />
                    )}
                  </div>
                </article>
              ))
            )}
          </div>

          <div className="hidden md:block">
            <Table>
              <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                <TableRow>
                  <TableHead className="text-xs text-[#717171]">Mã phòng ban</TableHead>
                  <TableHead className="text-xs text-[#717171]">Tên phòng ban</TableHead>
                  <TableHead className="text-xs text-[#717171]">Phòng ban cấp trên</TableHead>
                  <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                  <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {departments.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-xs text-[#717171]">
                      Chưa có phòng ban nào được tạo.
                    </TableCell>
                  </TableRow>
                ) : (
                  departments.map((dept) => (
                    <TableRow
                      key={dept.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell className="font-mono font-bold text-xs text-[#222222]">
                        {dept.code}
                      </TableCell>
                      <TableCell className="font-semibold text-xs text-[#222222]">
                        {dept.name}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171]">
                        {resolveParentDepartmentLabel(departments, dept.parentId)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={dept.isActive ? 'success' : 'secondary'}>
                          {formatActiveBooleanLabel(dept.isActive)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <InteractiveHoverButton
                            variant="ghost"
                            size="sm"
                            text="Sửa"
                            icon={<Pencil size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenEditDepartment(dept)}
                          />
                          {dept.isActive ? (
                            <InteractiveHoverButton
                              variant="danger"
                              size="sm"
                              text="Ngừng hoạt động"
                              icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => {
                                onClearError();
                                setPendingAction({ department: dept, action: 'deactivate' });
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
                                setPendingAction({ department: dept, action: 'activate' });
                              }}
                            />
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={Boolean(pendingAction)}
        onOpenChange={(open) => {
          if (!open && !isSubmitting) setPendingAction(null);
        }}
        title={
          pendingAction?.action === 'deactivate'
            ? 'Xác nhận ngừng hoạt động phòng ban'
            : 'Xác nhận kích hoạt lại phòng ban'
        }
        description={
          pendingAction?.action === 'deactivate'
            ? `Phòng ban "${pendingAction.department.name}" (${pendingAction.department.code}) sẽ ngừng hoạt động. Chỉ có thể ngừng hoạt động khi phòng ban không còn đơn vị con, nhân sự hoặc tài liệu đang hoạt động.`
            : `Phòng ban "${pendingAction?.department.name ?? ''}" (${pendingAction?.department.code ?? ''}) sẽ hoạt động trở lại và xuất hiện trong danh sách lựa chọn.`
        }
        confirmLabel={pendingAction?.action === 'deactivate' ? 'Ngừng hoạt động' : 'Kích hoạt lại'}
        variant={pendingAction?.action === 'deactivate' ? 'danger' : 'primary'}
        isLoading={isSubmitting}
        onConfirm={async () => {
          if (!pendingAction) return;
          setIsSubmitting(true);
          try {
            const ok =
              pendingAction.action === 'deactivate'
                ? await onDeactivateDepartment(pendingAction.department)
                : await onActivateDepartment(pendingAction.department);
            if (ok) setPendingAction(null);
          } finally {
            setIsSubmitting(false);
          }
        }}
      />
    </>
  );
}
