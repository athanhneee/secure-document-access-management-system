'use client';

import { CheckCircle2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export interface ServerSimulationResponse {
  decision: 'PERMIT' | 'DENY';
  reasonCode: string;
  obligations?: Array<{ type: string; minutes?: number }>;
  matchedRules?: string[];
  matchedRuleIds?: string[];
  policyVersion?: string;
  evaluationTimeMs?: number;
}

interface ServerSimulatorResultCardProps {
  serverResult: ServerSimulationResponse;
}

/**
 * Thuật toán: Hiển thị Kết Quả Đánh Giá Chính Sách Từ PDP Máy Chủ (`ServerSimulatorResultCard`)
 * Mục đích: Trình bày rõ quyết định `PERMIT`/`DENY`, mã lý do, độ trễ đánh giá, danh sách quy tắc khớp và nghĩa vụ thực thi trả về từ `/abac/simulate`.
 */
export function ServerSimulatorResultCard({ serverResult }: ServerSimulatorResultCardProps) {
  const matchedList = serverResult.matchedRules ?? serverResult.matchedRuleIds ?? [];

  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#ebebeb] pb-2.5">
        <div className="flex flex-wrap items-center gap-2">
          {serverResult.decision === 'PERMIT' ? (
            <CheckCircle2
              size={16}
              strokeWidth={1.75}
              className="text-[#008A05]"
              aria-hidden="true"
            />
          ) : (
            <XCircle size={16} strokeWidth={1.75} className="text-[#C13515]" aria-hidden="true" />
          )}
          <Badge variant={serverResult.decision === 'PERMIT' ? 'success' : 'danger'}>
            {serverResult.decision}
          </Badge>
          <span className="font-mono text-[#717171]">
            Reason: <strong className="text-[#222222]">{serverResult.reasonCode}</strong>
          </span>
        </div>
        <span className="font-mono text-[#717171]">
          Thời gian đánh giá:{' '}
          <strong className="text-[#222222]">{serverResult.evaluationTimeMs}ms</strong>
        </span>
      </div>

      <div className="flex flex-wrap gap-3 text-xs text-[#717171]">
        <span>
          Quy tắc khớp:{' '}
          <strong className="font-mono text-[#222222]">
            {matchedList.length > 0 ? matchedList.join(', ') : '—'}
          </strong>
        </span>
        <span>·</span>
        <span>
          Nghĩa vụ:{' '}
          <strong className="font-mono text-[#008489]">
            {serverResult.obligations && serverResult.obligations.length > 0
              ? serverResult.obligations.map((o) => o.type).join(', ')
              : 'Không có'}
          </strong>
        </span>
      </div>
    </div>
  );
}
