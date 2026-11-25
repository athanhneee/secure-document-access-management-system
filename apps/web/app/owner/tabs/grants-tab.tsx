'use client';

import { Plus, AlertOctagon } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
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
  canCreateGrant?: boolean;
  canRevokeGrant?: boolean;
  onOpenDirectGrant: () => void;
  onOpenRevoke: (grant: AccessGrantItem) => void;
}

export function GrantsTab({
  grants,
  canCreateGrant = true,
  canRevokeGrant = true,
  onOpenDirectGrant,
  onOpenRevoke,
}: GrantsTabProps) {
  return (
    <Card>
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Giấy phép truy cập ({grants.length})
        </CardTitle>
        {canCreateGrant && (
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text="Cấp quyền trực tiếp"
            icon={<Plus size={16} strokeWidth={2} aria-hidden="true" />}
            onClick={onOpenDirectGrant}
            className="shrink-0"
          />
        )}
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Đối tượng được cấp</TableHead>
              <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
              <TableHead className="text-xs text-[#717171]">Quyền hạn</TableHead>
              <TableHead className="text-xs text-[#717171]">Thời hạn hiệu lực</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thu hồi khẩn cấp</TableHead>
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
                    <div className="text-[13px] font-bold text-[#717171]">
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
                        <Badge key={p} variant="secondary" className="text-[13px]">
                          {p}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-[#222222] font-bold">
                    <div>Từ: {new Date(grant.validFrom).toLocaleDateString('vi-VN')}</div>
                    <div className="text-[#717171]">
                      Đến: {new Date(grant.validUntil).toLocaleDateString('vi-VN')}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={grant.status === 'ACTIVE' ? 'success' : 'destructive'}
                      className="text-[13px]"
                    >
                      {grant.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {grant.status === 'ACTIVE' && canRevokeGrant && (
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
      </CardContent>
    </Card>
  );
}
