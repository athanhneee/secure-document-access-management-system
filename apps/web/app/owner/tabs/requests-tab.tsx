'use client';

import { Check, X } from 'lucide-react';
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
import type { AccessRequestItem } from '../types';

interface RequestsTabProps {
  requests: AccessRequestItem[];
  onOpenApprove: (req: AccessRequestItem) => void;
  onReject: (req: AccessRequestItem) => void;
}

export function RequestsTab({ requests, onOpenApprove, onReject }: RequestsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">Hàng đợi yêu cầu cấp quyền</CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Xét duyệt yêu cầu đọc hoặc tải tài liệu mật kèm khoảng thời gian sử dụng từ các phòng ban
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Người yêu cầu / Phòng ban</TableHead>
                <TableHead className="text-xs text-[#717171]">Tài liệu mục tiêu</TableHead>
                <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời gian yêu cầu</TableHead>
                <TableHead className="text-xs text-[#717171]">Lý do nghiệp vụ</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Quyết định</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {requests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                    Không có yêu cầu cấp quyền nào đang chờ duyệt
                  </TableCell>
                </TableRow>
              ) : (
                requests.map((req) => (
                  <TableRow
                    key={req.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell>
                      <div className="font-semibold text-xs text-[#222222]">
                        {req.requestorName}
                      </div>
                      <div className="text-[11px] text-[#717171]">{req.requestorDepartment}</div>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] max-w-xs truncate">
                      {req.documentTitle}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{req.requestedAction}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {req.requestedFrom && req.requestedUntil ? (
                        <div>
                          <div>{new Date(req.requestedFrom).toLocaleDateString('vi-VN')}</div>
                          <div className="text-[#E07912]">
                            đến {new Date(req.requestedUntil).toLocaleDateString('vi-VN')}
                          </div>
                        </div>
                      ) : (
                        <span className="text-[#717171]">Mặc định 7 ngày</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-[#222222] max-w-sm">
                      {req.justification}
                    </TableCell>
                    <TableCell className="text-right">
                      {req.status === 'PENDING' ? (
                        <div className="flex items-center justify-end gap-1.5">
                          <InteractiveHoverButton
                            size="sm"
                            variant="primary"
                            text="Cấp quyền"
                            icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
                            onClick={() => onOpenApprove(req)}
                          />
                          <InteractiveHoverButton
                            size="sm"
                            variant="danger"
                            text="Từ chối"
                            icon={<X size={16} strokeWidth={2} aria-hidden="true" />}
                            onClick={() => onReject(req)}
                          />
                        </div>
                      ) : (
                        <Badge variant="outline" className="text-[10px] text-[#717171]">
                          {req.status}
                        </Badge>
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
