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
import { Play, Server, Sparkles } from 'lucide-react';
import type { VisualPolicyRule, TargetAction } from './abac-models';
import {
  buildSimulationPreset,
  evaluatePolicySimulation,
  type SimulationSubject,
  type SimulationResource,
  type SimulationEnvironment,
  type SimulationPresetName,
  type SimulationResult,
} from './simulator-evaluator';
import { SimulatorContextForm } from './simulator-context-form';
import { SimulatorTracePanel } from './simulator-trace-panel';
import { ServerSimulatorPanel } from './server-simulator-panel';

interface PolicySimulatorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeRule: VisualPolicyRule;
}

/**
 * Thuật toán: Bộ Giả Lập Điểm Quyết Định Chính Sách ABAC Kép — Trình Duyệt & Máy Chủ (`PolicySimulatorDialog`)
 * Mục đích: Kiểm thử tức thời cây AST nháp ngay trên trình duyệt hoặc thực thi mô phỏng chính thức qua `POST /abac/simulate` trên dữ liệu CSDL máy chủ.
 */
export function PolicySimulatorDialog({
  open,
  onOpenChange,
  activeRule,
}: PolicySimulatorDialogProps) {
  const [simMode, setSimMode] = useState<'draft' | 'server'>('draft');
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

  const applyPreset = (presetName: SimulationPresetName) => {
    const preset = buildSimulationPreset(presetName);
    setSubject(preset.subject);
    setResource(preset.resource);
    setEnvironment(preset.environment);
    setResult(null);
  };

  const runEvaluation = () => {
    setResult(evaluatePolicySimulation(activeRule, action, subject, resource, environment));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto bg-[#ffffff] border-[#ebebeb] p-6 text-[#222222]">
        <DialogHeader>
          <div className="flex flex-wrap items-center justify-between gap-2 pr-6">
            <div className="flex items-center gap-2">
              <Sparkles
                size={20}
                strokeWidth={1.75}
                className="text-[#FF385C]"
                aria-hidden="true"
              />
              <DialogTitle className="text-lg font-bold text-[#222222]">
                Trình Giả Lập & Kiểm Thử PDP Thời Gian Thực (Live Policy Simulator)
              </DialogTitle>
            </div>

            <div className="inline-flex items-center rounded-full border border-[#ebebeb] bg-[#f7f7f7] p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setSimMode('draft')}
                className={`px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer ${
                  simMode === 'draft'
                    ? 'bg-[#ffffff] text-[#222222] shadow-2xs'
                    : 'text-[#717171] hover:text-[#222222]'
                }`}
              >
                Nháp AST Cục bộ
              </button>
              <button
                type="button"
                onClick={() => setSimMode('server')}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer ${
                  simMode === 'server'
                    ? 'bg-[#ffffff] text-[#008489] shadow-2xs'
                    : 'text-[#717171] hover:text-[#222222]'
                }`}
              >
                <Server size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>PDP Máy chủ</span>
              </button>
            </div>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Kiểm thử tức thời quy tắc chính sách{' '}
            <strong className="text-[#222222] font-mono">{activeRule.code}</strong> trên trình duyệt
            hoặc đối chiếu trực tiếp với PDP máy chủ.
          </DialogDescription>
        </DialogHeader>

        {simMode === 'draft' ? (
          <>
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

            <SimulatorContextForm
              action={action}
              setAction={setAction}
              subject={subject}
              setSubject={setSubject}
              resource={resource}
              setResource={setResource}
              environment={environment}
              setEnvironment={setEnvironment}
            />

            <div className="flex justify-center pt-2">
              <Button
                type="button"
                onClick={runEvaluation}
                className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white px-8 h-9 text-xs font-semibold shadow-sm flex items-center gap-2"
              >
                <Play size={16} strokeWidth={1.75} className="fill-current" aria-hidden="true" />
                <span>Thực Thi Đánh Giá PDP (Evaluate Rule)</span>
              </Button>
            </div>

            {result && <SimulatorTracePanel result={result} />}
          </>
        ) : (
          <ServerSimulatorPanel defaultEnvironment={environment} />
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
