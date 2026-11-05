'use client';

import { Play } from 'lucide-react';
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
import type { DetectionRuleItem } from '../types';

interface DetectionRulesTabProps {
  detectionRules: DetectionRuleItem[];
  onRunDetection: () => void;
}

export function DetectionRulesTab({ detectionRules, onRunDetection }: DetectionRulesTabProps) {
  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3">
        <div>
          <CardTitle className="text-base text-[#222222]">
            Quy tắc phát hiện bất thường tự động
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Cấu hình ngưỡng số lần (threshold), cửa sổ thời gian (window) và thời gian hạ nhiệt
            (cooldown)
          </CardDescription>
        </div>
        <InteractiveHoverButton
          size="sm"
          variant="danger"
          text="Kích hoạt quét toàn bộ ngay"
          icon={<Play size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={onRunDetection}
        />
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Mã quy tắc</TableHead>
                <TableHead className="text-xs text-[#717171]">Tên quy tắc</TableHead>
                <TableHead className="text-xs text-[#717171]">Mức nghiêm trọng</TableHead>
                <TableHead className="text-xs text-[#717171]">Ngưỡng (Threshold)</TableHead>
                <TableHead className="text-xs text-[#717171]">Cửa sổ (Phút)</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
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
                    <TableCell className="font-bold text-xs text-[#222222]">
                      {resolvedCode}
                    </TableCell>
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
                      {r.threshold} lần
                    </TableCell>
                    <TableCell className="text-xs font-bold text-[#222222]">
                      {r.windowMinutes}m
                    </TableCell>
                    <TableCell>
                      <Badge variant={enabled ? 'success' : 'neutral'}>
                        {enabled ? 'Kích hoạt' : 'Đã tắt'}
                      </Badge>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
