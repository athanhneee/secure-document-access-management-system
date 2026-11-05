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
import type { AttributeDefinitionRow } from '../types';

interface AbacAttributesPanelProps {
  attributes: AttributeDefinitionRow[];
}

export function AbacAttributesPanel({ attributes }: AbacAttributesPanelProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Định nghĩa Thuộc tính Kiểm soát Quyền (Attribute Definitions)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Các thuộc tính Subject, Resource và Environment phục vụ đánh giá quy chế bảo mật
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mã thuộc tính</TableHead>
                <TableHead className="text-xs text-[#717171]">Tên thuộc tính</TableHead>
                <TableHead className="text-xs text-[#717171]">Kiểu dữ liệu</TableHead>
                <TableHead className="text-xs text-[#717171]">
                  Các tùy chọn & Thứ tự bậc (Rank)
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {attributes.map((attr) => (
                <TableRow key={attr.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-mono font-bold text-xs text-[#008A05]">
                    {attr.code}
                  </TableCell>
                  <TableCell className="text-xs font-semibold text-[#222222]">
                    {attr.name}
                  </TableCell>
                  <TableCell className="text-xs text-[#717171]">
                    {attr.data_type || 'STRING'}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      {attr.attribute_options?.map((opt) => (
                        // CONFLICT-RESOLVED: Loại bỏ nền bg-[#f7f7f7] trên Badge để giữ chuẩn phẳng staff-001 theo rules/ui-design-system.md.
                        <Badge key={opt.id || opt.code} variant="outline" className="text-[10px]">
                          {opt.code && opt.name && opt.code !== opt.name
                            ? `${opt.code} — ${opt.name}`
                            : opt.name || opt.code}{' '}
                          {opt.numeric_rank !== null &&
                            opt.numeric_rank !== undefined &&
                            `(Rank ${opt.numeric_rank})`}
                        </Badge>
                      ))}
                    </div>
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
