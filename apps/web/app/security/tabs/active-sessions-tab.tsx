'use client';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { DocumentSessionItem } from '../types';

interface ActiveSessionsTabProps {
  documentSessions: DocumentSessionItem[];
  terminatingSessionId: string | null;
  onTerminateSession: (sessionId: string) => void;
}

export function ActiveSessionsTab({
  documentSessions,
  terminatingSessionId,
  onTerminateSession,
}: ActiveSessionsTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader>
        <CardTitle className="text-base text-[#222222]">
          Phiên truy cập tài liệu đang hoạt động
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Giám sát các phiên đọc trực tuyến có nhúng watermark và thu hồi phiên truy cập tức thời
          khi phát hiện bất thường
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                <TableHead className="text-xs text-[#717171]">Người dùng</TableHead>
                <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                <TableHead className="text-xs text-[#717171]">Bắt đầu lúc</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {documentSessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                    Không có phiên truy cập tài liệu nào đang hoạt động
                  </TableCell>
                </TableRow>
              ) : (
                documentSessions.map((sess) => (
                  <TableRow
                    key={sess.id}
                    className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                  >
                    <TableCell className="font-semibold text-xs text-[#222222]">
                      <div>{sess.documentTitle}</div>
                      <div className="text-[13px] text-[#717171] font-normal">
                        {sess.documentCode} · v{sess.versionNo}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      <div className="font-medium">{sess.fullName}</div>
                      <div className="text-[13px] text-[#717171]">{sess.username}</div>
                    </TableCell>
                    <TableCell className="text-xs font-mono text-[#717171]">
                      {sess.ipAddress}
                    </TableCell>
                    <TableCell className="text-xs text-[#717171]">
                      {new Date(sess.startedAt).toLocaleString('vi-VN')}
                    </TableCell>
                    <TableCell>
                      <Badge variant={sess.status === 'ACTIVE' ? 'success' : 'neutral'}>
                        {sess.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      {sess.status === 'ACTIVE' && (
                        <InteractiveHoverButton
                          size="sm"
                          variant="destructive"
                          text="Ngắt phiên"
                          onClick={() => onTerminateSession(sess.id)}
                          isLoading={terminatingSessionId === sess.id}
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
