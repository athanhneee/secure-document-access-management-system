'use client';

import { Check, ChevronLeft, ChevronRight, RefreshCw, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  formatPermissionActionLabel,
  formatRequestStatusLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import type { AccessRequestItem } from '../types';

interface RequestsTabProps {
  requests: AccessRequestItem[];
  requestsPage?: number | undefined;
  requestsTotal?: number | undefined;
  requestsTotalPages?: number | undefined;
  isLoadingRequests?: boolean | undefined;
  onLoadPage?: ((page: number) => void) | undefined;
  canDecideRequest?: boolean;
  onOpenApprove: (req: AccessRequestItem) => void;
  onOpenReject: (req: AccessRequestItem) => void;
  onClearError: () => void;
}

/**
 * Thuật toán: Hàng Đợi Xét Duyệt Yêu Cầu Cấp Quyền Chủ Sở Hữu Có Phân Trang `> 20` & Modal Lý Do Từ Chối (`RequestsTab`, BUG-102)
 */
export function RequestsTab({
  requests,
  requestsPage = 1,
  requestsTotal,
  requestsTotalPages = 1,
  isLoadingRequests = false,
  onLoadPage,
  canDecideRequest = true,
  onOpenApprove,
  onOpenReject,
  onClearError,
}: RequestsTabProps) {
  const effectiveTotal = typeof requestsTotal === 'number' ? requestsTotal : requests.length;

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb]">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Danh sách yêu cầu quyền truy cập ({effectiveTotal})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {isLoadingRequests && requests.length === 0 ? (
          <div className="py-10 flex flex-col items-center justify-center gap-2 text-xs text-[#717171]">
            <RefreshCw
              size={20}
              strokeWidth={1.75}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <span>Đang tải danh sách yêu cầu truy cập…</span>
          </div>
        ) : requests.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            Không có yêu cầu quyền truy cập nào đang chờ duyệt.
          </div>
        ) : (
          <>
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {requests.map((req) => (
                <article key={req.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                  <div className="flex items-center justify-between gap-2">
                    <Badge variant="secondary">
                      {formatPermissionActionLabel(req.requestedAction)}
                    </Badge>
                    <Badge variant={req.status === 'PENDING' ? 'warning' : 'outline'}>
                      {formatRequestStatusLabel(req.status)}
                    </Badge>
                  </div>

                  <div className="space-y-0.5 min-w-0">
                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {req.documentTitle}
                    </h3>
                    <p className="text-xs text-[#717171]">
                      {req.requestorName} · {req.requestorDepartment}
                    </p>
                  </div>

                  <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Thời hạn</span>
                      <span className="font-medium text-[#222222] text-right tabular-nums">
                        {req.requestedFrom && req.requestedUntil
                          ? `${formatSafeDateVi(req.requestedFrom)} → ${formatSafeDateVi(req.requestedUntil)}`
                          : 'Theo mặc định mức mật'}
                      </span>
                    </div>
                  </div>

                  {req.justification && (
                    <p className="text-xs text-[#717171] leading-relaxed break-words">
                      <strong className="text-[#222222]">Lý do:</strong> {req.justification}
                    </p>
                  )}

                  {req.status === 'PENDING' && canDecideRequest && (
                    <div className="grid grid-cols-2 gap-2 pt-0.5">
                      <InteractiveHoverButton
                        size="sm"
                        variant="primary"
                        text="Cấp quyền"
                        icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
                        onClick={() => onOpenApprove(req)}
                        className="w-full"
                      />
                      <InteractiveHoverButton
                        size="sm"
                        variant="danger"
                        text="Từ chối"
                        icon={<X size={16} strokeWidth={2} aria-hidden="true" />}
                        onClick={() => {
                          onClearError();
                          onOpenReject(req);
                        }}
                        className="w-full"
                      />
                    </div>
                  )}
                </article>
              ))}
            </div>

            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">
                      Người yêu cầu / Phòng ban
                    </TableHead>
                    <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                    <TableHead className="text-xs text-[#717171]">Quyền yêu cầu</TableHead>
                    <TableHead className="text-xs text-[#717171]">Thời hạn đề nghị</TableHead>
                    <TableHead className="text-xs text-[#717171]">Lý do nghiệp vụ</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {requests.map((req) => (
                    <TableRow
                      key={req.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell>
                        <div className="font-semibold text-xs text-[#222222]">
                          {req.requestorName}
                        </div>
                        <div className="text-xs text-[#717171]">{req.requestorDepartment}</div>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222] max-w-xs truncate">
                        {req.documentTitle}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {formatPermissionActionLabel(req.requestedAction)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        {req.requestedFrom && req.requestedUntil ? (
                          <div>
                            <div>{formatSafeDateVi(req.requestedFrom)}</div>
                            <div className="text-[#717171] font-semibold">
                              đến {formatSafeDateVi(req.requestedUntil)}
                            </div>
                          </div>
                        ) : (
                          <span className="text-[#717171]">Theo mặc định mức mật</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-[#222222] max-w-sm">
                        {req.justification}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        {req.status === 'PENDING' && canDecideRequest ? (
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
                              onClick={() => {
                                onClearError();
                                onOpenReject(req);
                              }}
                            />
                          </div>
                        ) : (
                          <Badge variant="outline">{formatRequestStatusLabel(req.status)}</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {onLoadPage && (requestsPage > 1 || requestsTotalPages > 1 || effectiveTotal > 0) && (
          <div className="px-4 py-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
            <span>
              Tổng số: <strong className="text-[#222222]">{effectiveTotal}</strong> yêu cầu
            </span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={requestsPage <= 1 || isLoadingRequests}
                onClick={() => onLoadPage(Math.max(1, requestsPage - 1))}
              />
              <span className="font-semibold text-[#222222] whitespace-nowrap tabular-nums">
                Trang {requestsPage} / {Math.max(1, requestsTotalPages)}
              </span>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={requestsPage >= requestsTotalPages || isLoadingRequests}
                onClick={() => onLoadPage(requestsPage + 1)}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
