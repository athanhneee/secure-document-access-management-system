'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Network,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
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
  formatAlertSeverityLabel,
  formatDetectionRuleLabel,
  formatSafeDateVi,
  formatServiceHealthLabel,
} from '@/lib/ui-labels';
import type { NetworkDlpStatus, SecurityAlertItem } from '../types';
import { NetworkDlpBlueprint, NetworkDlpOverview } from './network-dlp-overview';

interface NetworkDlpTabProps {
  dlpAlerts: SecurityAlertItem[];
  totalDlpAlerts: number;
  dlpPage?: number | undefined;
  onDlpPageChange?: ((page: number) => void) | undefined;
  dlpStatus: NetworkDlpStatus;
  tabError?: string | null | undefined;
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

const DLP_PAGE_SIZE = 20;

function getDlpSeverityVariant(severity: SecurityAlertItem['severity']) {
  if (severity === 'CRITICAL') return 'destructive' as const;
  if (severity === 'HIGH') return 'warning' as const;
  return 'info' as const;
}

/**
 * Thuật toán: Giám Sát Chống Thất Thoát Dữ Liệu Mạng (DLP) Kèm Phân Trang `dlpPage` & Thẻ Di Động `375px` (`NetworkDlpTab`)
 * Mục đích: Hỗ trợ phân trang đầy đủ (`dlpPage`) thay vì cắt cứng 20 dòng đầu và kết xuất danh sách thẻ dọc `md:hidden` trên màn hình `375px`.
 */
export function NetworkDlpTab({
  dlpAlerts,
  totalDlpAlerts,
  dlpPage: controlledPage,
  onDlpPageChange,
  dlpStatus,
  tabError,
  onSelectAlert,
}: NetworkDlpTabProps) {
  const [internalDlpPage, setInternalDlpPage] = useState(1);
  const dlpPage = controlledPage ?? internalDlpPage;
  const effectiveTotal = Math.max(totalDlpAlerts, dlpAlerts.length);
  const totalPages = Math.max(1, Math.ceil(effectiveTotal / DLP_PAGE_SIZE));
  const safeDlpPage = Math.min(dlpPage, totalPages);

  const visibleDlpAlerts =
    !controlledPage && dlpAlerts.length > DLP_PAGE_SIZE
      ? dlpAlerts.slice((safeDlpPage - 1) * DLP_PAGE_SIZE, safeDlpPage * DLP_PAGE_SIZE)
      : dlpAlerts;

  const handlePageChange = (nextPage: number) => {
    const clamped = Math.min(totalPages, Math.max(1, nextPage));
    if (onDlpPageChange) {
      onDlpPageChange(clamped);
    } else {
      setInternalDlpPage(clamped);
    }
  };

  const gatewayHealth = dlpStatus.gatewayHealth;
  const healthBadgeVariant =
    gatewayHealth === 'ONLINE'
      ? 'success'
      : gatewayHealth === 'DEGRADED'
        ? 'warning'
        : 'destructive';
  const healthLabel = formatServiceHealthLabel(gatewayHealth);

  const modeBadgeVariant =
    dlpStatus.enforcementMode === 'BLOCK'
      ? 'danger'
      : dlpStatus.enforcementMode === 'AUDIT_ONLY'
        ? 'warning'
        : 'neutral';
  const modeBadgeLabel =
    dlpStatus.enforcementMode === 'BLOCK'
      ? 'Chế độ chặn vi phạm (BLOCK)'
      : dlpStatus.enforcementMode === 'AUDIT_ONLY'
        ? 'Chế độ chỉ giám sát (AUDIT_ONLY)'
        : dlpStatus.enforcementMode === 'DISABLED'
          ? 'DLP đang tắt theo cấu hình'
          : 'Mất kết nối dịch vụ DLP';

  const emptyStateNotice =
    gatewayHealth === 'ONLINE' ? (
      <div className="flex items-center justify-center gap-2">
        <ShieldCheck
          size={20}
          strokeWidth={1.75}
          className="text-[#008A05] shrink-0"
          aria-hidden="true"
        />
        <span className="font-medium text-[#222222]">
          Cổng giám sát DLP đang hoạt động ({modeBadgeLabel}) · Chưa ghi nhận vi phạm rò rỉ dữ liệu.
        </span>
      </div>
    ) : (
      <div className="flex items-center justify-center gap-2">
        <AlertTriangle
          size={20}
          strokeWidth={1.75}
          className="text-[#C13515] shrink-0"
          aria-hidden="true"
        />
        <span className="font-medium text-[#222222]">
          Dịch vụ giám sát DLP mạng hiện chưa sẵn sàng ({healthLabel} · {modeBadgeLabel}). Hãy kiểm
          tra tiến trình Worker DLP.
        </span>
      </div>
    );

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
            <Network size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Giám sát chống thất thoát dữ liệu mạng (DLP)</span>
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Badge variant={healthBadgeVariant}>{healthLabel}</Badge>
            <Badge variant={modeBadgeVariant}>{modeBadgeLabel}</Badge>
          </div>
        </div>

        {tabError && (
          <Alert variant="destructive" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2">{tabError}</AlertDescription>
          </Alert>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        <NetworkDlpOverview dlpStatus={dlpStatus} />

        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
              Cảnh báo chống thất thoát dữ liệu ({effectiveTotal})
            </h3>
            <span className="text-xs text-[#717171]">
              {dlpStatus.checkedAt
                ? `Kiểm tra lúc ${formatSafeDateVi(dlpStatus.checkedAt, { includeTime: true })}`
                : 'Ghi nhận từ hệ thống giám sát luồng dữ liệu'}
            </span>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] overflow-hidden">
            {visibleDlpAlerts.length === 0 ? (
              <div className="px-4 py-7 text-center text-[#717171] text-xs">{emptyStateNotice}</div>
            ) : (
              <>
                <div className="md:hidden divide-y divide-[#ebebeb]">
                  {visibleDlpAlerts.map((alert) => (
                    <article key={alert.id} className="p-3.5 space-y-2.5 bg-[#ffffff] text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <Badge variant={getDlpSeverityVariant(alert.severity)}>
                          {formatAlertSeverityLabel(alert.severity)}
                        </Badge>
                        <span className="text-[#717171] tabular-nums">
                          {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                        </span>
                      </div>
                      <div className="space-y-0.5 min-w-0">
                        <div className="font-semibold text-sm text-[#222222] break-words">
                          {alert.title}
                        </div>
                        <div className="text-[#717171]">
                          {formatDetectionRuleLabel(alert.ruleCode)}
                        </div>
                      </div>
                      <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[#717171]">Đối tượng</span>
                          <span className="font-medium text-[#222222] truncate">
                            {alert.detectedUserName || 'Chưa định danh'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[#717171]">Địa chỉ IP</span>
                          <span className="font-mono text-[#222222] tabular-nums">
                            {alert.ipAddress}
                          </span>
                        </div>
                      </div>
                      <InteractiveHoverButton
                        size="sm"
                        variant="secondary"
                        text="Chi tiết"
                        icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => onSelectAlert(alert)}
                        className="w-full"
                      />
                    </article>
                  ))}
                </div>

                <div className="hidden md:block">
                  <Table>
                    <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                      <TableRow>
                        <TableHead className="text-xs text-[#717171]">Mức độ</TableHead>
                        <TableHead className="text-xs text-[#717171]">Hành vi phát hiện</TableHead>
                        <TableHead className="text-xs text-[#717171]">
                          Đối tượng liên quan
                        </TableHead>
                        <TableHead className="text-xs text-[#717171]">Địa chỉ IP nguồn</TableHead>
                        <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
                        <TableHead className="text-xs text-[#717171] text-right">
                          Thao tác
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {visibleDlpAlerts.map((alert) => (
                        <TableRow
                          key={alert.id}
                          className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                        >
                          <TableCell>
                            <Badge variant={getDlpSeverityVariant(alert.severity)}>
                              {formatAlertSeverityLabel(alert.severity)}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="font-semibold text-xs text-[#222222]">
                              {alert.title}
                            </div>
                            <div className="text-xs text-[#717171]">
                              {formatDetectionRuleLabel(alert.ruleCode)}
                            </div>
                          </TableCell>
                          <TableCell className="text-xs text-[#222222]">
                            {alert.detectedUserName || 'Chưa định danh'}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-[#717171]">
                            {alert.ipAddress}
                          </TableCell>
                          <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                            {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                          </TableCell>
                          <TableCell className="text-right whitespace-nowrap">
                            <InteractiveHoverButton
                              size="sm"
                              variant="secondary"
                              text="Chi tiết"
                              icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => onSelectAlert(alert)}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            )}

            {totalPages > 1 && (
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-3.5 py-2.5 text-xs text-[#717171]">
                <span className="tabular-nums">
                  Trang {safeDlpPage} / {totalPages} · Tổng {effectiveTotal} cảnh báo
                </span>
                <div className="flex items-center gap-1.5">
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="secondary"
                    text="Trang trước"
                    icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                    disabled={safeDlpPage <= 1}
                    onClick={() => handlePageChange(safeDlpPage - 1)}
                  />
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="secondary"
                    text="Trang sau"
                    icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                    disabled={safeDlpPage >= totalPages}
                    onClick={() => handlePageChange(safeDlpPage + 1)}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        <NetworkDlpBlueprint />
      </CardContent>
    </Card>
  );
}
