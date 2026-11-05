'use client';

import { CheckCircle2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import type { SimulationResult } from './simulator-evaluator';

interface SimulatorTracePanelProps {
  result: SimulationResult;
}

export function SimulatorTracePanel({ result }: SimulatorTracePanelProps) {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#ebebeb] pb-3">
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-[#717171]">Quyết định PDP:</span>
          {result.decision === 'PERMIT' ? (
            <Badge variant="success" className="text-sm">
              CHO PHÉP (PERMIT)
            </Badge>
          ) : (
            <Badge variant="danger" className="text-sm">
              TỪ CHỐI (DENY)
            </Badge>
          )}
        </div>
        <div className="text-xs font-mono text-[#717171]">
          Reason Code: <strong className="text-[#222222]">{result.reasonCode}</strong>
        </div>
      </div>

      {result.obligations.length > 0 && (
        <div>
          <span className="text-[11px] font-semibold text-[#222222] block mb-1.5">
            Nghĩa vụ đi kèm (Obligations):
          </span>
          <div className="flex flex-wrap gap-3">
            {result.obligations.map((ob, idx) => (
              <Badge key={idx} variant="info">
                {ob.type === 'MAX_SESSION_MINUTES' ? `Giới hạn phiên: ${ob.minutes} phút` : ob.type}
              </Badge>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <span className="text-[11px] font-semibold text-[#222222] block">
          Phân tích cây điều kiện logic (Evaluation Tree):
        </span>
        <div className="space-y-2">
          {result.groupEvaluations.map((group) => (
            <div
              key={group.groupId}
              className={`rounded-[12px] p-2.5 border text-xs ${
                group.satisfied ? 'border-[#008A05]/30 bg-[#008A05]/5' : 'border-[#ebebeb] bg-white'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-[#222222]">
                  Nhóm điều kiện #{group.groupId} (Mệnh đề liên hội AND)
                </span>
                {group.satisfied ? (
                  <span className="text-[11px] font-bold text-[#008A05] flex items-center gap-1">
                    <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Thỏa mãn (TRUE)</span>
                  </span>
                ) : (
                  <span className="text-[11px] font-bold text-[#C13515] flex items-center gap-1">
                    <XCircle size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Chưa đạt (FALSE)</span>
                  </span>
                )}
              </div>
              <div className="space-y-1 pl-2 font-mono text-[11px]">
                {group.conditionResults.map((c) => (
                  <div
                    key={c.conditionId}
                    className="flex items-center justify-between text-[#717171]"
                  >
                    <div className="flex items-center gap-1.5">
                      {c.matched ? (
                        <CheckCircle2
                          size={16}
                          strokeWidth={1.75}
                          className="text-[#008A05] shrink-0"
                          aria-hidden="true"
                        />
                      ) : (
                        <XCircle
                          size={16}
                          strokeWidth={1.75}
                          className="text-[#C13515] shrink-0"
                          aria-hidden="true"
                        />
                      )}
                      <span className="text-[#222222]">{c.attribute}</span>
                      <span className="text-[#FF385C]">{c.operator}</span>
                      <span>{JSON.stringify(c.expected)}</span>
                    </div>
                    <span className="text-[#717171]">
                      Giá trị thực tế: <strong>{JSON.stringify(c.actual)}</strong>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
