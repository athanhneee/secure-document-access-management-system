'use client';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
}

export function DepartmentsTab({ departments }: DepartmentsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">Cơ cấu phòng ban tổ chức</CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Phân định ranh giới sở hữu tài liệu và phạm vi ủy quyền truy cập
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mã phòng ban</TableHead>
                <TableHead className="text-xs text-[#717171]">Tên phòng ban</TableHead>
                <TableHead className="text-xs text-[#717171]">Phòng ban cấp trên</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {departments.map((dept) => (
                <TableRow key={dept.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-bold text-xs text-[#222222]">{dept.code}</TableCell>
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    {dept.name}
                  </TableCell>
                  <TableCell className="text-xs text-[#717171]">
                    {resolveParentDepartmentLabel(departments, dept.parentId)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={dept.isActive ? 'success' : 'secondary'}>
                      {dept.isActive ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
