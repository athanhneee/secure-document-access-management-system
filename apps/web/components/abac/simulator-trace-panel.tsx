'use client';

import { CheckCircle2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  formatAbacReasonLabel,
  formatObligationLabel,
  formatPolicyEffectLabel,
} from '@/lib/ui-labels';
import { ATTRIBUTE_REGISTRY, OPERATOR_LABELS, type PolicyOperator } from './abac-models';
import type { SimulationResult } from './simulator-evaluator';

interface SimulatorTracePanelProps {
  result: SimulationResult;
}

export function SimulatorTracePanel({ result }: SimulatorTracePanelProps) {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#ebebeb] pb-3">
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-[#717171]">Quyết định đánh giá:</span>
          {result.decision === 'PERMIT' ? (
            <Badge variant="success" className="text-sm">
              {formatPolicyEffectLabel(result.decision)}
            </Badge>
          ) : (
            <Badge variant="danger" className="text-sm">
              {formatPolicyEffectLabel(result.decision)}
            </Badge>
          )}
        </div>
        <div className="text-xs text-[#717171]">
          Lý do:{' '}
          <strong className="text-[#222222]">{formatAbacReasonLabel(result.reasonCode)}</strong>
        </div>
      </div>

      {result.obligations.length > 0 && (
        <div>
          <span className="text-xs font-semibold text-[#222222] block mb-1.5">
            Nghĩa vụ đi kèm:
          </span>
          <div className="flex flex-wrap gap-3">
            {result.obligations.map((ob, idx) => (
              <Badge key={idx} variant="info">
                {formatObligationLabel(
                  ob.type,
                  ob.type === 'MAX_SESSION_MINUTES' ? ob.minutes : undefined,
                )}
              </Badge>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <span className="text-xs font-semibold text-[#222222] block">
          Chi tiết đánh giá điều kiện:
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
                  Nhóm điều kiện #{group.groupId} (Thỏa mãn đồng thời)
                </span>
                {group.satisfied ? (
                  <span className="text-xs font-bold text-[#008A05] flex items-center gap-1">
                    <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Thỏa mãn</span>
                  </span>
                ) : (
                  <span className="text-xs font-bold text-[#C13515] flex items-center gap-1">
                    <XCircle size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Chưa đạt</span>
                  </span>
                )}
              </div>
              <div className="space-y-1 pl-2 text-xs">
                {group.conditionResults.map((c) => (
                  <div
                    key={c.conditionId}
                    className="flex flex-wrap items-center justify-between gap-1.5 text-[#717171]"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
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
                      <span className="text-[#222222] font-medium">
                        {ATTRIBUTE_REGISTRY[c.attribute]?.label ?? c.attribute}
                      </span>
                      <span className="text-[#E31C5F] font-semibold">
                        {OPERATOR_LABELS[c.operator as PolicyOperator] ?? c.operator}
                      </span>
                      <span className="font-mono">{JSON.stringify(c.expected)}</span>
                    </div>
                    <span className="text-[#717171]">
                      Giá trị thực tế:{' '}
                      <strong className="font-mono text-[#222222]">
                        {JSON.stringify(c.actual)}
                      </strong>
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
