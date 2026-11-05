'use client';

import { Plus, AlertOctagon } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import type { AccessGrantItem } from '../types';

interface GrantsTabProps {
  grants: AccessGrantItem[];
  onOpenDirectGrant: () => void;
  onOpenRevoke: (grant: AccessGrantItem) => void;
}

export function GrantsTab({ grants, onOpenDirectGrant, onOpenRevoke }: GrantsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Giấy phép truy cập có thời hạn (Access Grants)
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Cấp trực tiếp cho User hoặc Role; quyền hết hạn hoặc bị thu hồi sẽ chấm dứt mọi phiên
            đọc lập tức
          </CardDescription>
        </div>
        <InteractiveHoverButton
          variant="primary"
          size="sm"
          text="Cấp quyền trực tiếp"
          icon={<Plus size={16} strokeWidth={2} aria-hidden="true" />}
          onClick={onOpenDirectGrant}
        />
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Đối tượng được cấp</TableHead>
                <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                <TableHead className="text-xs text-[#717171]">Quyền hạn</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời hạn hiệu lực</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">
                  Thu hồi khẩn cấp
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {grants.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                    Chưa có giấy phép truy cập nào được khởi tạo
                  </TableCell>
                </TableRow>
              ) : (
                grants.map((grant) => (
                  <TableRow
                    key={grant.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell>
                      <div className="font-semibold text-xs text-[#222222]">
                        {grant.principalName}
                      </div>
                      <div className="text-[10px] font-bold text-[#717171]">
                        {grant.principalType}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] max-w-xs truncate">
                      {grant.documentTitle}
                    </TableCell>
                    <TableCell>
                      {/* CONFLICT-RESOLVED: Gỡ bỏ lớp viền/nền hộp khỏi Badge quyền hạn để tuân thủ chuẩn nhãn phẳng staff-001 (rules/ui-design-system.md §3) */}
                      <div className="flex flex-wrap gap-3">
                        {grant.permissions.map((p) => (
                          <Badge key={p} variant="secondary" className="text-[10px]">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] font-bold">
                      <div>Từ: {new Date(grant.validFrom).toLocaleDateString('vi-VN')}</div>
                      <div className="text-[#E07912]">
                        Đến: {new Date(grant.validUntil).toLocaleDateString('vi-VN')}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={grant.status === 'ACTIVE' ? 'success' : 'destructive'}
                        className="text-[10px]"
                      >
                        {grant.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      {grant.status === 'ACTIVE' && (
                        <InteractiveHoverButton
                          size="sm"
                          variant="danger"
                          text="Thu hồi"
                          icon={<AlertOctagon size={16} strokeWidth={2} aria-hidden="true" />}
                          onClick={() => onOpenRevoke(grant)}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
