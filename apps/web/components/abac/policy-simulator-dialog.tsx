'use client';

import { useMemo, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle, Play, Server, Sparkles } from 'lucide-react';
import {
  buildCategorySelectOptions,
  buildDepartmentSelectOptions,
  type DynamicCategoryOption,
  type DynamicDepartmentOption,
  type TargetAction,
  type VisualPolicyRule,
} from './abac-models';
import {
  buildSimulationPreset,
  evaluatePolicySetSimulation,
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

const TARGET_ALL_ACTIVE = '__ALL_ACTIVE__';
const TARGET_DRAFT_RULE = '__DRAFT_RULE__';

interface PolicySimulatorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeRule?: VisualPolicyRule | undefined;
  policySet?: readonly VisualPolicyRule[] | undefined;
  selectableRules?: readonly VisualPolicyRule[] | undefined;
  departments?: readonly DynamicDepartmentOption[] | undefined;
  businessCategories?: readonly DynamicCategoryOption[] | undefined;
  canSimulateOnServer?: boolean | undefined;
}

/**
 * Thuật toán: Bộ Giả Lập Điểm Quyết Định Chính Sách ABAC Kép — Tập Luật CSDL, Bản Nháp & Máy Chủ (`PolicySimulatorDialog`)
 * Mục đích: Đánh giá toàn bộ tập chính sách đang thực thi trong CSDL (kèm Bell-LaPadula & `DENY_OVERRIDES`),
 * kiểm thử riêng từng bản nháp DNF hoặc đối chiếu trực tiếp với máy chủ qua `POST /abac/simulate`.
 */
export function PolicySimulatorDialog({
  open,
  onOpenChange,
  activeRule,
  policySet,
  selectableRules,
  departments,
  businessCategories,
  canSimulateOnServer = true,
}: PolicySimulatorDialogProps) {
  const departmentOptions = useMemo(() => buildDepartmentSelectOptions(departments), [departments]);
  const categoryOptions = useMemo(
    () => buildCategorySelectOptions(businessCategories),
    [businessCategories],
  );
  const defaultDeptId = String(departmentOptions[0]?.value ?? '1');
  const defaultCategory = String(categoryOptions[0]?.value ?? 'GENERAL_OPERATIONS');

  const activeDbRules = useMemo(() => policySet ?? [], [policySet]);
  const individualDbRules = useMemo(
    () => (selectableRules && selectableRules.length > 0 ? selectableRules : activeDbRules),
    [selectableRules, activeDbRules],
  );
  const defaultTargetKey = activeRule ? TARGET_DRAFT_RULE : TARGET_ALL_ACTIVE;

  const [simMode, setSimMode] = useState<'draft' | 'server'>('draft');
  const [selectedTarget, setSelectedTarget] = useState<string>(defaultTargetKey);
  const effectiveMode: 'draft' | 'server' = canSimulateOnServer ? simMode : 'draft';
  const [action, setAction] = useState<TargetAction>('VIEW');
  const [subject, setSubject] = useState<SimulationSubject>({
    clearanceRank: 3,
    departmentId: defaultDeptId,
    employmentStatus: 'ACTIVE',
    projects: ['PROJECT_ALPHA'],
  });
  const [resource, setResource] = useState<SimulationResource>({
    classificationRank: 3,
    departmentId: defaultDeptId,
    category: defaultCategory,
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

  const effectiveTarget = useMemo(() => {
    if (selectedTarget === TARGET_DRAFT_RULE && activeRule) return TARGET_DRAFT_RULE;
    if (selectedTarget === TARGET_ALL_ACTIVE) return TARGET_ALL_ACTIVE;
    if (individualDbRules.some((r) => (r.id ?? r.code) === selectedTarget)) return selectedTarget;
    return defaultTargetKey;
  }, [selectedTarget, activeRule, individualDbRules, defaultTargetKey]);

  const effectiveSubject = useMemo<SimulationSubject>(
    () => ({
      ...subject,
      departmentId: departmentOptions.some((d) => String(d.value) === subject.departmentId)
        ? subject.departmentId
        : defaultDeptId,
    }),
    [subject, departmentOptions, defaultDeptId],
  );
  const effectiveResource = useMemo<SimulationResource>(
    () => ({
      ...resource,
      departmentId: departmentOptions.some((d) => String(d.value) === resource.departmentId)
        ? resource.departmentId
        : defaultDeptId,
      category: categoryOptions.some((c) => String(c.value) === resource.category)
        ? resource.category
        : defaultCategory,
    }),
    [resource, departmentOptions, categoryOptions, defaultDeptId, defaultCategory],
  );

  const selectedSingleRule = useMemo<VisualPolicyRule | undefined>(() => {
    if (effectiveTarget === TARGET_DRAFT_RULE) return activeRule;
    if (effectiveTarget === TARGET_ALL_ACTIVE) return undefined;
    return individualDbRules.find((r) => (r.id ?? r.code) === effectiveTarget);
  }, [effectiveTarget, activeRule, individualDbRules]);

  const applyPreset = (presetName: SimulationPresetName) => {
    const preset = buildSimulationPreset(presetName, departments, businessCategories);
    setSubject(preset.subject);
    setResource(preset.resource);
    setEnvironment(preset.environment);
    setResult(null);
  };

  const runEvaluation = () => {
    if (effectiveTarget === TARGET_ALL_ACTIVE) {
      setResult(
        evaluatePolicySetSimulation(
          activeDbRules,
          action,
          effectiveSubject,
          effectiveResource,
          environment,
        ),
      );
      return;
    }
    const targetRule = selectedSingleRule ?? activeRule;
    if (!targetRule) {
      setResult(
        evaluatePolicySetSimulation(
          activeDbRules,
          action,
          effectiveSubject,
          effectiveResource,
          environment,
        ),
      );
      return;
    }
    setResult(
      evaluatePolicySimulation(
        targetRule,
        action,
        effectiveSubject,
        effectiveResource,
        environment,
      ),
    );
  };

  const descriptionTargetLabel =
    effectiveTarget === TARGET_ALL_ACTIVE
      ? `toàn bộ ${activeDbRules.length} quy tắc đang thực thi trong CSDL (kèm Bell-LaPadula & DENY_OVERRIDES)`
      : `quy tắc ${selectedSingleRule?.code ?? activeRule?.code ?? ''}`;

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
                Mô phỏng và kiểm thử chính sách truy cập
              </DialogTitle>
            </div>

            {canSimulateOnServer && (
              <div className="inline-flex items-center rounded-full border border-[#ebebeb] bg-[#f7f7f7] p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setSimMode('draft')}
                  className={`min-h-11 sm:min-h-8 px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer ${
                    effectiveMode === 'draft'
                      ? 'bg-[#ffffff] text-[#222222] shadow-2xs'
                      : 'text-[#717171] hover:text-[#222222]'
                  }`}
                >
                  Kiểm thử cục bộ (PDP)
                </button>
                <button
                  type="button"
                  onClick={() => setSimMode('server')}
                  className={`inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer ${
                    effectiveMode === 'server'
                      ? 'bg-[#ffffff] text-[#008489] shadow-2xs'
                      : 'text-[#717171] hover:text-[#222222]'
                  }`}
                >
                  <Server size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Kiểm thử trên máy chủ</span>
                </button>
              </div>
            )}
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Đánh giá tức thời <strong className="text-[#222222]">{descriptionTargetLabel}</strong>{' '}
            hoặc đối chiếu trực tiếp với máy chủ.
          </DialogDescription>
        </DialogHeader>

        {effectiveMode === 'draft' ? (
          <>
            {!activeRule && activeDbRules.length === 0 && (
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
                  Chưa có quy tắc chính sách nào đang kích hoạt được nạp cục bộ (mô phỏng cục bộ sẽ
                  trả Mặc định từ chối).
                  {canSimulateOnServer
                    ? ' Hãy chuyển sang tab "Kiểm thử trên máy chủ" để đánh giá trực tiếp trên PDP.'
                    : ''}
                </AlertDescription>
              </Alert>
            )}

            {(activeDbRules.length > 0 || individualDbRules.length > 0) && (
              <div className="flex flex-col sm:flex-row sm:items-center gap-2 p-2.5 rounded-[16px] bg-[#ffffff] border border-[#ebebeb] text-xs">
                <label
                  htmlFor="sim-target-policy"
                  className="font-semibold text-[#222222] shrink-0"
                >
                  Phạm vi đánh giá:
                </label>
                <select
                  id="sim-target-policy"
                  value={effectiveTarget}
                  onChange={(e) => {
                    setSelectedTarget(e.target.value);
                    setResult(null);
                  }}
                  className="w-full sm:flex-1 min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
                >
                  {activeRule && (
                    <option value={TARGET_DRAFT_RULE}>
                      Bản nháp đang soạn thảo: {activeRule.name} ({activeRule.code})
                    </option>
                  )}
                  <option value={TARGET_ALL_ACTIVE}>
                    Toàn bộ chính sách đang thực thi trong CSDL ({activeDbRules.length} quy tắc)
                  </option>
                  {individualDbRules.map((ruleItem) => {
                    const key = ruleItem.id ?? ruleItem.code;
                    return (
                      <option key={key} value={key}>
                        Riêng quy tắc: {ruleItem.name} ({ruleItem.code})
                      </option>
                    );
                  })}
                </select>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-[16px] bg-[#f7f7f7] border border-[#ebebeb] text-xs">
              <span className="font-semibold text-[#717171] shrink-0">Kịch bản thử nghiệm:</span>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => applyPreset('trusted_employee')}
                  className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
                >
                  Nhân sự tin cậy (mạng nội bộ, có MFA)
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => applyPreset('remote_suspicious')}
                  className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
                >
                  Truy cập rủi ro cao từ xa
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => applyPreset('cross_dept')}
                  className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C]"
                >
                  Yêu cầu chéo phòng ban
                </Button>
              </div>
            </div>

            <SimulatorContextForm
              action={action}
              setAction={setAction}
              subject={effectiveSubject}
              setSubject={setSubject}
              resource={effectiveResource}
              setResource={setResource}
              environment={environment}
              setEnvironment={setEnvironment}
              departmentOptions={departmentOptions}
              categoryOptions={categoryOptions}
            />

            <div className="flex justify-center pt-2">
              <Button
                type="button"
                onClick={runEvaluation}
                className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white px-8 min-h-11 sm:h-9 text-xs font-semibold shadow-sm flex items-center gap-2"
              >
                <Play size={16} strokeWidth={1.75} className="fill-current" aria-hidden="true" />
                <span>Chạy mô phỏng đánh giá</span>
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
            className="rounded-full text-xs min-h-11 sm:h-9 border-[#dddddd]"
          >
            Đóng
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
