'use client';

import { AlertTriangle, CheckCircle2, ShieldAlert, XCircle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import {
  formatAbacReasonLabel,
  formatObligationLabel,
  formatPermissionActionLabel,
  formatPolicyEffectLabel,
} from '@/lib/ui-labels';
import { ATTRIBUTE_REGISTRY, OPERATOR_LABELS, type PolicyOperator } from './abac-models';
import type { SimulationGroupEvaluation, SimulationResult } from './simulator-evaluator';

interface SimulatorTracePanelProps {
  result: SimulationResult;
}

function GroupEvaluationList({ groups }: { groups: SimulationGroupEvaluation[] }) {
  return (
    <div className="space-y-2">
      {groups.map((group) => (
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
                  <strong className="font-mono text-[#222222]">{JSON.stringify(c.actual)}</strong>
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Thuật toán: Hiển Thị Vết Đánh Giá PDP Cục Bộ (Bell-LaPadula, Step-Up MFA & Danh Sách Quy Tắc CSDL) (`SimulatorTracePanel`)
 */
export function SimulatorTracePanel({ result }: SimulatorTracePanelProps) {
  const hasRuleSetTrace = Boolean(result.ruleEvaluations && result.ruleEvaluations.length > 0);

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

      {result.bellLaPadulaBlocked && (
        <Alert
          variant="destructive"
          className="rounded-[12px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
        >
          <ShieldAlert size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
          <AlertDescription className="ml-2">
            Chặn cứng theo bất biến <strong>Bell-LaPadula (No Read Up)</strong>: cấp thẩm quyền của
            người dùng thấp hơn cấp độ mật tài liệu, bỏ qua toàn bộ luật cho phép phía sau.
          </AlertDescription>
        </Alert>
      )}

      {result.reasonCode === 'STEP_UP_MFA_REQUIRED' && (
        <Alert
          variant="warning"
          className="rounded-[12px] border border-[#E07912]/30 bg-[#E07912]/10 text-[#222222] text-xs"
        >
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912]"
            aria-hidden="true"
          />
          <AlertDescription className="ml-2">
            Quy tắc yêu cầu xác thực đa yếu tố (<strong>STEP_UP_MFA_REQUIRED</strong>): phiên cần
            hoàn tất xác thực MFA bổ sung trước khi được phép truy cập tài liệu này.
          </AlertDescription>
        </Alert>
      )}

      {result.matchedRuleCodes.length > 0 && (
        <div className="text-xs text-[#717171]">
          Quy tắc khớp:{' '}
          <strong className="font-mono text-[#222222]">{result.matchedRuleCodes.join(', ')}</strong>
        </div>
      )}

      {result.obligations.length > 0 && (
        <div>
          <span className="text-xs font-semibold text-[#222222] block mb-1.5">
            Nghĩa vụ đi kèm:
          </span>
          <div className="flex flex-wrap gap-2">
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

      {hasRuleSetTrace ? (
        <div className="space-y-2.5">
          <span className="text-xs font-semibold text-[#222222] block">
            Chi tiết đánh giá từng quy tắc trong CSDL (ưu tiên DENY_OVERRIDES):
          </span>
          <div className="space-y-2.5">
            {result.ruleEvaluations!.map((ruleEval) => (
              <div
                key={ruleEval.ruleId}
                className={`rounded-[12px] border p-3 space-y-2 text-xs ${
                  ruleEval.matched
                    ? ruleEval.effect === 'DENY'
                      ? 'border-[#C13515]/30 bg-[#C13515]/5'
                      : 'border-[#008A05]/30 bg-[#008A05]/5'
                    : 'border-[#ebebeb] bg-[#ffffff]'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={ruleEval.effect === 'PERMIT' ? 'success' : 'destructive'}>
                      {formatPolicyEffectLabel(ruleEval.effect)}
                    </Badge>
                    <span className="font-bold text-[#222222]">{ruleEval.ruleName}</span>
                    <span className="font-mono text-[#717171]">
                      ({ruleEval.ruleCode} · ưu tiên {ruleEval.priority})
                    </span>
                  </div>
                  <span
                    className={`font-semibold ${
                      ruleEval.matched ? 'text-[#222222]' : 'text-[#717171]'
                    }`}
                  >
                    {!ruleEval.actionTargeted
                      ? `Bỏ qua (chỉ áp dụng ${formatPermissionActionLabel(ruleEval.targetAction)})`
                      : ruleEval.matched
                        ? 'Khớp điều kiện'
                        : 'Không khớp'}
                  </span>
                </div>
                {ruleEval.actionTargeted && ruleEval.groupEvaluations.length > 0 && (
                  <GroupEvaluationList groups={ruleEval.groupEvaluations} />
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        result.groupEvaluations.length > 0 && (
          <div className="space-y-2">
            <span className="text-xs font-semibold text-[#222222] block">
              Chi tiết đánh giá điều kiện:
            </span>
            <GroupEvaluationList groups={result.groupEvaluations} />
          </div>
        )
      )}
    </div>
  );
}
