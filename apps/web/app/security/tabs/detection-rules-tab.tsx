'use client';

import { AlertTriangle, Play, Settings } from 'lucide-react';
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
import { formatAlertSeverityLabel } from '@/lib/ui-labels';
import type { DetectionRuleItem } from '../types';

interface DetectionRulesTabProps {
  detectionRules: DetectionRuleItem[];
  isRunningDetection?: boolean | undefined;
  tabError?: string | null | undefined;
  canManageRules?: boolean;
  onRunDetection: (ruleCodes?: string[]) => void | Promise<void>;
  onEditRule: (rule: DetectionRuleItem) => void;
}

/**
 * Thuật toán: Quản Trị Bảng Tham Số Luật Phát Hiện Bất Thường SOC Kèm Quét Đích Danh Từng Quy Tắc (`DetectionRulesTab`)
 * Mục đích: Chấm dứt ghi đè `windowMinutes: 60` (#17), cho phép quét đúng khung thời gian từng quy tắc hoặc quét đơn lẻ (`ruleCodes`, N08) và hiển thị cấu hình giờ Việt Nam cho `OFF_HOURS_ACCESS` (#26).
 */
export function DetectionRulesTab({
  detectionRules,
  isRunningDetection = false,
  tabError,
  canManageRules = true,
  onRunDetection,
  onEditRule,
}: DetectionRulesTabProps) {
  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Quy tắc phát hiện bất thường ({detectionRules.length})
          </CardTitle>
          {canManageRules && (
            <InteractiveHoverButton
              size="sm"
              variant="danger"
              text="Quét bất thường ngay"
              icon={<Play size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isRunningDetection}
              disabled={isRunningDetection}
              onClick={() => void onRunDetection()}
              className="shrink-0"
            />
          )}
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
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Mã quy tắc</TableHead>
              <TableHead className="text-xs text-[#717171]">Tên &amp; mô tả</TableHead>
              <TableHead className="text-xs text-[#717171]">Mức nghiêm trọng</TableHead>
              <TableHead className="text-xs text-[#717171]">Ngưỡng</TableHead>
              <TableHead className="text-xs text-[#717171]">Khung theo dõi</TableHead>
              <TableHead className="text-xs text-[#717171]">Giãn cách</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detectionRules.map((r, i) => {
              const resolvedCode = r.ruleCode || r.code || '—';
              const enabled = r.isEnabled !== false;
              const isOffHours = resolvedCode === 'OFF_HOURS_ACCESS';
              const startVn = (Number(r.parameters?.['startHourUtc'] ?? 0) + 7) % 24;
              const endVn = (Number(r.parameters?.['endHourUtc'] ?? 11) + 7) % 24;

              return (
                <TableRow
                  key={resolvedCode !== '—' ? resolvedCode : i}
                  className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                >
                  <TableCell className="font-mono font-bold text-xs text-[#222222]">
                    {resolvedCode}
                  </TableCell>
                  <TableCell className="max-w-xs">
                    <div className="font-semibold text-xs text-[#222222]">{r.name}</div>
                    {r.description && (
                      <div className="text-xs text-[#717171] line-clamp-2">{r.description}</div>
                    )}
                    {isOffHours && (
                      <div className="text-xs text-[#008489] font-medium mt-0.5">
                        Giờ hành chính VN: {String(startVn).padStart(2, '0')}:00 –{' '}
                        {String(endVn).padStart(2, '0')}:59 (T2–T6)
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        r.severity === 'CRITICAL'
                          ? 'destructive'
                          : r.severity === 'HIGH'
                            ? 'warning'
                            : 'info'
                      }
                    >
                      {formatAlertSeverityLabel(r.severity)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#222222]">
                    {r.threshold ?? r.thresholdCount ?? 5} lần
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#222222]">
                    {r.windowMinutes} phút
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#717171]">
                    {r.cooldownMinutes ?? 30} phút
                  </TableCell>
                  <TableCell>
                    <Badge variant={enabled ? 'success' : 'neutral'}>
                      {resolvedCode === 'AUDIT_INTEGRITY_COMPROMISED'
                        ? 'Bắt buộc'
                        : enabled
                          ? 'Đang bật'
                          : 'Đã tắt'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    {canManageRules && (
                      <div className="inline-flex items-center gap-1.5">
                        {enabled && resolvedCode !== '—' && (
                          <InteractiveHoverButton
                            size="sm"
                            variant="ghost"
                            text="Quét"
                            icon={<Play size={16} strokeWidth={1.75} aria-hidden="true" />}
                            disabled={isRunningDetection}
                            onClick={() => void onRunDetection([resolvedCode])}
                          />
                        )}
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Cấu hình"
                          icon={<Settings size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onEditRule(r)}
                        />
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
