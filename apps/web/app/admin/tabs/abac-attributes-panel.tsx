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
  DATE: 'Ngày giờ',
  DATETIME: 'Ngày giờ',
  ENUM: 'Danh mục',
  ARRAY: 'Danh sách',
  STRING_ARRAY: 'Danh sách chuỗi',
  IP_CIDR: 'Dải địa chỉ IP',
  TIME_RANGE: 'Khung thời gian',
};

/**
 * Thuật toán: Ánh Xạ Nhãn Kiểu Dữ Liệu Thuộc Tính ABAC Đầy Đủ Sang Tiếng Việt (`formatAttributeDataTypeLabel`, BUG-120)
 */
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
        {attributes.length === 0 ? (
          <div className="py-8 px-4 text-center text-xs text-[#717171]">
            Chưa có định nghĩa thuộc tính kiểm soát truy cập nào.
          </div>
        ) : (
          <>
            {/* Bố cục thẻ di động tối ưu 375px (BUG-120) */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {attributes.map((attr) => (
                <article key={attr.id} className="px-4 py-3.5 space-y-2.5 bg-[#ffffff]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-bold text-xs text-[#008A05] break-all">
                      {attr.code}
                    </span>
                    <Badge variant="secondary">
                      {formatAttributeDataTypeLabel(attr.data_type)}
                    </Badge>
                  </div>
                  <div className="text-sm font-semibold text-[#222222] leading-snug break-words">
                    {attr.name}
                  </div>
                  {attr.attribute_options && attr.attribute_options.length > 0 && (
                    <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 flex flex-wrap gap-x-3 gap-y-1.5">
                      {attr.attribute_options.map((opt) => (
                        <Badge key={opt.id || opt.code} variant="outline">
                          {opt.code && opt.name && opt.code !== opt.name
                            ? `${opt.code} — ${opt.name}`
                            : opt.name || opt.code}{' '}
                          {opt.numeric_rank !== null &&
                            opt.numeric_rank !== undefined &&
                            `(Cấp ${opt.numeric_rank})`}
                        </Badge>
                      ))}
                    </div>
                  )}
                </article>
              ))}
            </div>

            {/* Bảng dữ liệu máy tính */}
            <div className="hidden md:block overflow-x-auto">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Mã thuộc tính</TableHead>
                    <TableHead className="text-xs text-[#717171]">Tên thuộc tính</TableHead>
                    <TableHead className="text-xs text-[#717171]">Kiểu dữ liệu</TableHead>
                    <TableHead className="text-xs text-[#717171]">
                      Các tùy chọn và thứ tự cấp
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attributes.map((attr) => (
                    <TableRow
                      key={attr.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
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
                            // CONFLICT-RESOLVED: Loại bỏ nền bg-[#f7f7f7] và text-[13px] trên Badge để giữ chuẩn phẳng staff-001 (BUG-120).
                            <Badge key={opt.id || opt.code} variant="outline">
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
          </>
        )}
      </CardContent>
    </Card>
  );
}
