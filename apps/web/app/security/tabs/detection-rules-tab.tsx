'use client';

import { Play, Settings } from 'lucide-react';
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
import type { DetectionRuleItem } from '../types';

interface DetectionRulesTabProps {
  detectionRules: DetectionRuleItem[];
  onRunDetection: () => void | Promise<void>;
  onEditRule: (rule: DetectionRuleItem) => void;
}

/**
 * Thuật toán: Quản Trị Bảng Tham Số Luật Phát Hiện Bất Thường SOC (`DetectionRulesTab`)
 * Mục đích: Hiển thị 6 quy tắc phát hiện tự động kèm ngưỡng, cửa sổ thời gian, thời gian hạ nhiệt và nút mở `<dialog>` cấu hình trực tiếp.
 */
export function DetectionRulesTab({
  detectionRules,
  onRunDetection,
  onEditRule,
}: DetectionRulesTabProps) {
  return (
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Quy tắc phát hiện bất thường ({detectionRules.length})
        </CardTitle>
        <InteractiveHoverButton
          size="sm"
          variant="danger"
          text="Quét toàn bộ ngay"
          icon={<Play size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onRunDetection}
          className="shrink-0"
        />
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Mã quy tắc</TableHead>
              <TableHead className="text-xs text-[#717171]">Tên quy tắc</TableHead>
              <TableHead className="text-xs text-[#717171]">Mức nghiêm trọng</TableHead>
              <TableHead className="text-xs text-[#717171]">Ngưỡng</TableHead>
              <TableHead className="text-xs text-[#717171]">Cửa sổ</TableHead>
              <TableHead className="text-xs text-[#717171]">Hạ nhiệt</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detectionRules.map((r, i) => {
              const resolvedCode = r.ruleCode || r.code || '—';
              const enabled = r.isEnabled !== false;
              return (
                <TableRow
                  key={resolvedCode !== '—' ? resolvedCode : i}
                  className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                >
                  <TableCell className="font-bold text-xs text-[#222222]">{resolvedCode}</TableCell>
                  <TableCell className="font-semibold text-xs text-[#222222]">{r.name}</TableCell>
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
                      {r.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#222222]">
                    {r.threshold ?? r.thresholdCount ?? 5} lần
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#222222]">
                    {r.windowMinutes}m
                  </TableCell>
                  <TableCell className="text-xs font-bold text-[#717171]">
                    {r.cooldownMinutes ?? 30}m
                  </TableCell>
                  <TableCell>
                    <Badge variant={enabled ? 'success' : 'neutral'}>
                      {enabled ? 'Kích hoạt' : 'Đã tắt'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Cấu hình"
                      icon={<Settings size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onEditRule(r)}
                    />
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
