'use client';

import { Pencil, Plus } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
}

/**
 * Thuật toán: Hiển Thị & Quản Trị Cây Phân Cấp Phòng Ban Tổ Chức (`DepartmentsTab`)
 * Mục đích: Ánh xạ nhãn đơn vị cấp trên từ danh sách phẳng `departments` và kích hoạt hộp thoại tạo mới / cập nhật thông tin phòng ban theo OCC.
 */
export function DepartmentsTab({
  departments,
  onOpenCreateDepartment,
  onOpenEditDepartment,
}: DepartmentsTabProps) {
  return (
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
                <TableRow key={dept.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
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
                    <div className="flex items-center justify-end gap-1.5">
                      <InteractiveHoverButton
                        variant="ghost"
                        size="sm"
                        text="Sửa"
                        icon={<Pencil size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => onOpenEditDepartment(dept)}
                      />
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
