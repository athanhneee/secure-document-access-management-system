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

const ATTRIBUTE_DATA_TYPE_LABELS: Readonly<Record<string, string>> = {
  STRING: 'Chuỗi ký tự',
  NUMBER: 'Số',
  INTEGER: 'Số nguyên',
  BOOLEAN: 'Đúng / Sai',
  ENUM: 'Danh mục',
  ARRAY: 'Danh sách',
  STRING_ARRAY: 'Danh sách chuỗi',
  IP_CIDR: 'Dải địa chỉ IP',
  TIME_RANGE: 'Khung thời gian',
};

function formatAttributeDataTypeLabel(raw?: string | null): string {
  const key = (raw ?? 'STRING').trim().toUpperCase();
  return ATTRIBUTE_DATA_TYPE_LABELS[key] ?? raw ?? 'Chuỗi ký tự';
}

export function AbacAttributesPanel({ attributes }: AbacAttributesPanelProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Định nghĩa thuộc tính kiểm soát truy cập
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Các thuộc tính của người dùng, tài liệu và bối cảnh truy cập phục vụ đánh giá chính sách
          bảo mật.
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
                <TableHead className="text-xs text-[#717171]">Các tùy chọn và thứ tự cấp</TableHead>
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
                    {formatAttributeDataTypeLabel(attr.data_type)}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      {attr.attribute_options?.map((opt) => (
                        // CONFLICT-RESOLVED: Loại bỏ nền bg-[#f7f7f7] trên Badge để giữ chuẩn phẳng staff-001 theo rules/ui-design-system.md.
                        <Badge key={opt.id || opt.code} variant="outline" className="text-[13px]">
                          {opt.code && opt.name && opt.code !== opt.name
                            ? `${opt.code} — ${opt.name}`
                            : opt.name || opt.code}{' '}
                          {opt.numeric_rank !== null &&
                            opt.numeric_rank !== undefined &&
                            `(Cấp ${opt.numeric_rank})`}
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
