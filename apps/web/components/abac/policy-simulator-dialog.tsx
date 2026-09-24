'use client';

import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Play, Network, KeyRound, FileCheck2, CheckCircle2, XCircle, Sparkles } from 'lucide-react';
import type {
  VisualPolicyRule,
  VisualCondition,
  VisualObligation,
  TargetAction,
  TimeWindow,
} from './abac-models';
import { CLEARANCE_OPTIONS, DEPARTMENT_OPTIONS } from './abac-models';

interface PolicySimulatorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeRule: VisualPolicyRule;
}

interface SimulationSubject {
  clearanceRank: number;
  departmentId: string;
  employmentStatus: string;
  projects: string[];
}

interface SimulationResource {
  classificationRank: number;
  departmentId: string;
  category: string;
  status: string;
  ownerId: string;
}

interface SimulationEnvironment {
  currentTime: string; // HH:mm
  ip: string;
  trustedNetwork: boolean;
  deviceTrust: boolean;
  mfa: boolean;
  riskScore: number;
}

interface SimulationResult {
  decision: 'PERMIT' | 'DENY';
  reasonCode: string;
  matchedRuleCodes: string[];
  obligations: VisualObligation[];
  groupEvaluations: Array<{
    groupId: number;
    satisfied: boolean;
    conditionResults: Array<{
      conditionId: string;
      attribute: string;
      operator: string;
      expected: unknown;
      actual: unknown;
      matched: boolean;
    }>;
  }>;
}

export function PolicySimulatorDialog({
  open,
  onOpenChange,
  activeRule,
}: PolicySimulatorDialogProps) {
  // Context state
  const [action, setAction] = useState<TargetAction>('VIEW');

  const [subject, setSubject] = useState<SimulationSubject>({
    clearanceRank: 3,
    departmentId: 'IT_DEPT',
    employmentStatus: 'ACTIVE',
    projects: ['PROJECT_ALPHA'],
  });

  const [resource, setResource] = useState<SimulationResource>({
    classificationRank: 3,
    departmentId: 'IT_DEPT',
    category: 'SECURITY',
    status: 'ACTIVE',
    ownerId: '1',
  });

  const [environment, setEnvironment] = useState<SimulationEnvironment>({
    currentTime: '10:30',
    ip: '192.168.1.45',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 20,
  });

  const [result, setResult] = useState<SimulationResult | null>(null);

  // Quick Preset Presets for Simulation
  const applyPreset = (presetName: 'trusted_employee' | 'remote_suspicious' | 'cross_dept') => {
    if (presetName === 'trusted_employee') {
      setSubject({
        clearanceRank: 4,
        departmentId: 'IT_DEPT',
        employmentStatus: 'ACTIVE',
        projects: ['PROJECT_ALPHA'],
      });
      setResource({
        classificationRank: 3,
        departmentId: 'IT_DEPT',
        category: 'SECURITY',
        status: 'ACTIVE',
        ownerId: '1',
      });
      setEnvironment({
        currentTime: '14:00',
        ip: '192.168.1.100',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: 10,
      });
    } else if (presetName === 'remote_suspicious') {
      setSubject({
        clearanceRank: 2,
        departmentId: 'HR_DEPT',
        employmentStatus: 'ACTIVE',
        projects: [],
      });
      setResource({
        classificationRank: 4,
        departmentId: 'SECURITY_DEPT',
        category: 'SECURITY',
        status: 'ACTIVE',
        ownerId: '99',
      });
      setEnvironment({
        currentTime: '23:45',
        ip: '203.113.152.12',
        trustedNetwork: false,
        deviceTrust: false,
        mfa: false,
        riskScore: 85,
      });
    } else if (presetName === 'cross_dept') {
      setSubject({
        clearanceRank: 3,
        departmentId: 'HR_DEPT',
        employmentStatus: 'ACTIVE',
        projects: ['HR_REVAMP'],
      });
      setResource({
        classificationRank: 3,
        departmentId: 'FINANCE_DEPT',
        category: 'FINANCE',
        status: 'ACTIVE',
        ownerId: '5',
      });
      setEnvironment({
        currentTime: '09:15',
        ip: '192.168.1.55',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: 15,
      });
    }
    setResult(null);
  };

  // Evaluate rule locally against visual rule AST
  const runEvaluation = () => {
    const flatAttributes: Record<string, unknown> = {
      'subject.clearanceRank': subject.clearanceRank,
      'subject.departmentId': subject.departmentId,
      'subject.employmentStatus': subject.employmentStatus,
      'subject.projects': subject.projects,
      'resource.classificationRank': resource.classificationRank,
      'resource.departmentId': resource.departmentId,
      'resource.category': resource.category,
      'resource.status': resource.status,
      'resource.ownerId': resource.ownerId,
      'environment.currentTime': environment.currentTime,
      'environment.ip': environment.ip,
      'environment.trustedNetwork': environment.trustedNetwork,
      'environment.deviceTrust': environment.deviceTrust,
      'environment.mfa': environment.mfa,
      'environment.riskScore': environment.riskScore,
    };

    // Check target action match
    const actionMatches = activeRule.targetAction === 'ALL' || activeRule.targetAction === action;

    if (!actionMatches) {
      setResult({
        decision: 'DENY',
        reasonCode: 'ACTION_NOT_TARGETED',
        matchedRuleCodes: [],
        obligations: [],
        groupEvaluations: [],
      });
      return;
    }

    // Evaluate DNF groups: Groups are joined by OR.
    // Within each group, conditions are joined by AND.
    const groupEvaluations = activeRule.groups.map((group) => {
      const conditionResults = group.conditions.map((cond) => {
        const actual = flatAttributes[cond.attribute];
        const matched = evaluateCondition(cond, actual);
        return {
          conditionId: cond.id,
          attribute: cond.attribute,
          operator: cond.operator,
          expected: cond.expected,
          actual,
          matched,
        };
      });

      const satisfied = conditionResults.length > 0 && conditionResults.every((c) => c.matched);

      return {
        groupId: group.id,
        satisfied,
        conditionResults,
      };
    });

    const anyGroupSatisfied = groupEvaluations.some((g) => g.satisfied);

    if (anyGroupSatisfied) {
      if (activeRule.effect === 'PERMIT') {
        setResult({
          decision: 'PERMIT',
          reasonCode: 'RULE_PERMIT_MATCHED',
          matchedRuleCodes: [activeRule.code],
          obligations: activeRule.obligations,
          groupEvaluations,
        });
      } else {
        setResult({
          decision: 'DENY',
          reasonCode: 'EXPLICIT_DENY_RULE_MATCHED',
          matchedRuleCodes: [activeRule.code],
          obligations: activeRule.obligations,
          groupEvaluations,
        });
      }
    } else {
      // No group satisfied
      setResult({
        decision: 'DENY',
        reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
        matchedRuleCodes: [],
        obligations: [],
        groupEvaluations,
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto bg-[#ffffff] border-[#ebebeb] p-6 text-[#222222]">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-[#FF385C]" />
              <DialogTitle className="text-lg font-bold text-[#222222]">
                Trình Giả Lập & Kiểm Thử PDP Thời Gian Thực (Live Policy Simulator)
              </DialogTitle>
            </div>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Kiểm thử tức thời quy tắc chính sách{' '}
            <strong className="text-[#222222] font-mono">{activeRule.code}</strong> với các ngữ cảnh
            giả lập Subject, Resource và Environment.
          </DialogDescription>
        </DialogHeader>

        {/* Quick Presets Bar */}
        <div className="flex items-center gap-2 p-2.5 rounded-[16px] bg-[#f7f7f7] border border-[#ebebeb] text-xs">
          <span className="font-semibold text-[#717171] shrink-0">Kịch bản thử nghiệm:</span>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => applyPreset('trusted_employee')}
              className="h-7 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
            >
              Nhân sự An toàn (Mạng cơ quan, MFA)
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => applyPreset('remote_suspicious')}
              className="h-7 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
            >
              Truy cập Rủi ro cao từ xa
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => applyPreset('cross_dept')}
              className="h-7 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
            >
              Yêu cầu chéo phòng ban
            </Button>
          </div>
        </div>

        {/* Simulation Context Input Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {/* SUBJECT CONTEXT */}
          <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
            <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
              <KeyRound className="h-4 w-4 text-[#008489]" />
              <span>1. Ngữ cảnh Chủ thể (Subject)</span>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">
                Cấp bậc An ninh (Clearance):
              </div>
              <select
                value={subject.clearanceRank}
                onChange={(e) =>
                  setSubject((s) => ({ ...s, clearanceRank: Number(e.target.value) }))
                }
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] focus:border-[#FF385C]"
              >
                {CLEARANCE_OPTIONS.map((c) => (
                  <option key={String(c.value)} value={Number(c.value)}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">Phòng ban công tác:</div>
              <select
                value={subject.departmentId}
                onChange={(e) => setSubject((s) => ({ ...s, departmentId: e.target.value }))}
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] focus:border-[#FF385C]"
              >
                {DEPARTMENT_OPTIONS.map((d) => (
                  <option key={String(d.value)} value={String(d.value)}>
                    {d.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">Trạng thái nhân sự:</div>
              <select
                value={subject.employmentStatus}
                onChange={(e) => setSubject((s) => ({ ...s, employmentStatus: e.target.value }))}
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff]"
              >
                <option value="ACTIVE">Đang công tác (ACTIVE)</option>
                <option value="PROBATION">Thử việc (PROBATION)</option>
                <option value="SUSPENDED">Tạm đình chỉ (SUSPENDED)</option>
              </select>
            </div>
          </div>

          {/* RESOURCE CONTEXT */}
          <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
            <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
              <FileCheck2 className="h-4 w-4 text-[#FF385C]" />
              <span>2. Ngữ cảnh Tài nguyên (Resource)</span>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">
                Cấp độ mật tài liệu:
              </div>
              <select
                value={resource.classificationRank}
                onChange={(e) =>
                  setResource((r) => ({ ...r, classificationRank: Number(e.target.value) }))
                }
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] focus:border-[#FF385C]"
              >
                {CLEARANCE_OPTIONS.map((c) => (
                  <option key={String(c.value)} value={Number(c.value)}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">Phòng ban sở hữu:</div>
              <select
                value={resource.departmentId}
                onChange={(e) => setResource((r) => ({ ...r, departmentId: e.target.value }))}
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] focus:border-[#FF385C]"
              >
                {DEPARTMENT_OPTIONS.map((d) => (
                  <option key={String(d.value)} value={String(d.value)}>
                    {d.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">Hành động yêu cầu:</div>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as TargetAction)}
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] font-semibold text-[#FF385C]"
              >
                <option value="VIEW">XEM TRỰC TUYẾN (VIEW)</option>
                <option value="DOWNLOAD">TẢI BẢN SAO (DOWNLOAD)</option>
                <option value="SHARE">CHIA SẺ (SHARE)</option>
                <option value="MANAGE">QUẢN TRỊ (MANAGE)</option>
                <option value="DISCOVER">TÌM KIẾM (DISCOVER)</option>
              </select>
            </div>
          </div>

          {/* ENVIRONMENT CONTEXT */}
          <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
            <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
              <Network className="h-4 w-4 text-[#008A05]" />
              <span>3. Môi trường & Thiết bị</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-[11px] font-medium text-[#717171] mb-1">Mạng nội bộ:</div>
                <select
                  value={environment.trustedNetwork ? 'true' : 'false'}
                  onChange={(e) =>
                    setEnvironment((env) => ({ ...env, trustedNetwork: e.target.value === 'true' }))
                  }
                  className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2 bg-[#ffffff]"
                >
                  <option value="true">Tin cậy (Yes)</option>
                  <option value="false">Mạng ngoài (No)</option>
                </select>
              </div>

              <div>
                <div className="text-[11px] font-medium text-[#717171] mb-1">Xác thực MFA:</div>
                <select
                  value={environment.mfa ? 'true' : 'false'}
                  onChange={(e) =>
                    setEnvironment((env) => ({ ...env, mfa: e.target.value === 'true' }))
                  }
                  className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2 bg-[#ffffff]"
                >
                  <option value="true">Đã bật (Yes)</option>
                  <option value="false">Chưa bật (No)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-[11px] font-medium text-[#717171] mb-1">Giờ truy cập:</div>
                <input
                  type="time"
                  value={environment.currentTime}
                  onChange={(e) =>
                    setEnvironment((env) => ({ ...env, currentTime: e.target.value }))
                  }
                  className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff]"
                />
              </div>

              <div>
                <div className="text-[11px] font-medium text-[#717171] mb-1">
                  Điểm rủi ro (0-100):
                </div>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={environment.riskScore}
                  onChange={(e) =>
                    setEnvironment((env) => ({ ...env, riskScore: Number(e.target.value) }))
                  }
                  className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff]"
                />
              </div>
            </div>

            <div>
              <div className="text-[11px] font-medium text-[#717171] mb-1">Địa chỉ IP nguồn:</div>
              <input
                type="text"
                value={environment.ip}
                onChange={(e) => setEnvironment((env) => ({ ...env, ip: e.target.value }))}
                className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] font-mono text-[11px]"
              />
            </div>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex justify-center pt-2">
          <Button
            type="button"
            onClick={runEvaluation}
            className="rounded-full bg-[#FF385C] hover:bg-[#E03150] text-white px-8 h-9 text-xs font-semibold shadow-sm flex items-center gap-2"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>Thực Thi Đánh Giá PDP (Evaluate Rule)</span>
          </Button>
        </div>

        {/* PDP Decision Output Result */}
        {result && (
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

            {/* Obligations */}
            {result.obligations.length > 0 && (
              <div>
                <span className="text-[11px] font-semibold text-[#222222] block mb-1.5">
                  Nghĩa vụ đi kèm (Obligations):
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {result.obligations.map((ob, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#008489] bg-white border border-[#ebebeb] px-2.5 py-1 rounded-full"
                    >
                      <CheckCircle2 className="h-3 w-3 text-[#008A05]" />
                      <span>
                        {ob.type === 'MAX_SESSION_MINUTES'
                          ? `Giới hạn phiên: ${ob.minutes} phút`
                          : ob.type}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Logic Group Match Breakdown */}
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-[#222222] block">
                Phân tích cây điều kiện logic (Evaluation Tree):
              </span>
              <div className="space-y-2">
                {result.groupEvaluations.map((group) => (
                  <div
                    key={group.groupId}
                    className={`rounded-[12px] p-2.5 border text-xs ${
                      group.satisfied
                        ? 'border-[#008A05]/30 bg-[#008A05]/5'
                        : 'border-[#ebebeb] bg-white'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-bold text-[#222222]">
                        Nhóm điều kiện #{group.groupId} (Mệnh đề liên hội AND)
                      </span>
                      {group.satisfied ? (
                        <span className="text-[11px] font-bold text-[#008A05] flex items-center gap-1">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          <span>Thỏa mãn (TRUE)</span>
                        </span>
                      ) : (
                        <span className="text-[11px] font-bold text-[#C13515] flex items-center gap-1">
                          <XCircle className="h-3.5 w-3.5" />
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
                              <CheckCircle2 className="h-3 w-3 text-[#008A05] shrink-0" />
                            ) : (
                              <XCircle className="h-3 w-3 text-[#C13515] shrink-0" />
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
        )}

        <DialogFooter className="pt-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="rounded-full text-xs h-8 border-[#dddddd]"
          >
            Đóng Trình Giả Lập
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function evaluateCondition(cond: VisualCondition, actual: unknown): boolean {
  if (cond.operator === 'EXISTS') {
    return actual !== undefined && actual !== null && actual !== '';
  }

  if (actual === undefined || actual === null) {
    return false;
  }

  switch (cond.operator) {
    case 'EQ':
      return actual === cond.expected;
    case 'NEQ':
      return actual !== cond.expected;
    case 'GTE':
      return Number(actual) >= Number(cond.expected);
    case 'LTE':
      return Number(actual) <= Number(cond.expected);
    case 'BETWEEN':
      if (Array.isArray(cond.expected) && cond.expected.length === 2) {
        const num = Number(actual);
        return num >= Number(cond.expected[0]) && num <= Number(cond.expected[1]);
      }
      return false;
    case 'IN':
      if (Array.isArray(cond.expected)) {
        if (Array.isArray(actual)) {
          return actual.some((a) => (cond.expected as unknown[]).includes(a));
        }
        return (cond.expected as unknown[]).includes(actual);
      }
      return false;
    case 'NOT_IN':
      if (Array.isArray(cond.expected)) {
        if (Array.isArray(actual)) {
          return !actual.some((a) => (cond.expected as unknown[]).includes(a));
        }
        return !(cond.expected as unknown[]).includes(actual);
      }
      return false;
    case 'TIME_BETWEEN':
      if (typeof cond.expected === 'object' && cond.expected !== null) {
        const tw = cond.expected as TimeWindow;
        const current = String(actual); // HH:mm
        return current >= tw.start && current <= tw.end;
      }
      return false;
    case 'CIDR_MATCH':
      // Simplified simulation check: matches prefix or exact IP
      if (typeof cond.expected === 'string' && typeof actual === 'string') {
        const cidrPrefix = cond.expected.split('/')[0]!.split('.').slice(0, 3).join('.');
        return actual.startsWith(cidrPrefix);
      }
      return false;
    default:
      return false;
  }
}
