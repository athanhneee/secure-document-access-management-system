'use client';

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
import { computeRequestSpanDays } from '../helpers';
import type { MyRequestItem } from '../types';

interface MyRequestsTabProps {
  myRequests: MyRequestItem[];
  cancellingRequestId: string | null;
  onCancelRequest: (requestId: string) => void;
}

export function MyRequestsTab({
  myRequests,
  cancellingRequestId,
  onCancelRequest,
}: MyRequestsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Trạng thái yêu cầu cấp quyền cá nhân
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Theo dõi tiến độ phê duyệt từ các chủ sở hữu tài liệu
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tài liệu mục tiêu</TableHead>
                <TableHead className="text-xs text-[#717171]">Quyền yêu cầu</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời gian yêu cầu</TableHead>
                <TableHead className="text-xs text-[#717171]">Thời gian gửi</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái xử lý</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {myRequests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                    Bạn chưa gửi yêu cầu cấp quyền nào
                  </TableCell>
                </TableRow>
              ) : (
                myRequests.map((req) => (
                  <TableRow
                    key={req.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell className="font-semibold text-xs text-[#222222]">
                      {req.documentTitle}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{req.requestedAction}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {req.requestedFrom && req.requestedUntil ? (
                        <div className="flex flex-col text-xs">
                          <span className="font-medium text-[#222222]">
                            {new Date(req.requestedFrom).toLocaleDateString('vi-VN')} &rarr;{' '}
                            {new Date(req.requestedUntil).toLocaleDateString('vi-VN')}
                          </span>
                          <span className="text-[13px] text-[#717171]">
                            ({computeRequestSpanDays(req.requestedFrom, req.requestedUntil)} ngày)
                          </span>
                        </div>
                      ) : (
                        <span className="text-[#717171]">7 ngày (mặc định)</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-[#717171] font-bold">
                      {new Date(req.createdAt).toLocaleDateString('vi-VN')}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          req.status === 'PENDING'
                            ? 'warning'
                            : req.status === 'APPROVED'
                              ? 'success'
                              : req.status === 'CANCELLED'
                                ? 'neutral'
                                : 'destructive'
                        }
                      >
                        {req.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      {req.status === 'PENDING' && (
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Hủy yêu cầu"
                          onClick={() => onCancelRequest(req.id)}
                          isLoading={cancellingRequestId === req.id}
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
