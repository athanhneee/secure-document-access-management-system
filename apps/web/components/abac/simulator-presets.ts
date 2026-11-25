import type {
  DynamicCategoryOption,
  DynamicDepartmentOption,
  TargetAction,
  VisualObligation,
} from './abac-models';

export type SimulationPresetName = 'trusted_employee' | 'remote_suspicious' | 'cross_dept';

export interface SimulationSubject {
  clearanceRank: number;
  departmentId: string;
  employmentStatus: string;
  projects: string[];
}

export interface SimulationResource {
  classificationRank: number;
  departmentId: string;
  category: string;
  status: string;
  ownerId: string;
}

export interface SimulationEnvironment {
  currentTime: string;
  ip: string;
  trustedNetwork: boolean;
  deviceTrust: boolean;
  mfa: boolean;
  riskScore: number;
}

export interface SimulationConditionResult {
  conditionId: string;
  attribute: string;
  operator: string;
  expected: unknown;
  actual: unknown;
  matched: boolean;
}

export interface SimulationGroupEvaluation {
  groupId: number;
  satisfied: boolean;
  conditionResults: SimulationConditionResult[];
}

export interface SimulationRuleEvaluation {
  ruleId: string;
  ruleCode: string;
  ruleName: string;
  effect: 'PERMIT' | 'DENY';
  priority: number;
  targetAction: TargetAction;
  actionTargeted: boolean;
  matched: boolean;
  groupEvaluations: SimulationGroupEvaluation[];
}

export interface SimulationResult {
  decision: 'PERMIT' | 'DENY';
  reasonCode: string;
  matchedRuleCodes: string[];
  obligations: VisualObligation[];
  groupEvaluations: SimulationGroupEvaluation[];
  ruleEvaluations?: SimulationRuleEvaluation[];
  bellLaPadulaBlocked?: boolean;
}

/**
 * Algorithm / Thuật toán: Khởi tạo Vector Ngữ Cảnh Đối Chứng An Ninh Động Theo Phòng Ban & Danh Mục CSDL (`buildSimulationPreset`)
 * Mục đích: Tái lập nhanh 3 trạng thái kiểm thử điển hình sử dụng đúng ID phòng ban và mã danh mục thực tế từ CSDL thay vì mã giả cứng.
 */
export function buildSimulationPreset(
  presetName: SimulationPresetName,
  departments?: readonly DynamicDepartmentOption[],
  categories?: readonly DynamicCategoryOption[],
): {
  subject: SimulationSubject;
  resource: SimulationResource;
  environment: SimulationEnvironment;
} {
  const firstDeptId = String(departments?.[0]?.id ?? '1');
  const secondDeptId = String(departments?.[1]?.id ?? firstDeptId);
  const financeDeptId = String(
    departments?.find((d) => d.code.toUpperCase().includes('FINANCE'))?.id ?? secondDeptId,
  );
  const securityDeptId = String(
    departments?.find((d) => d.code.toUpperCase().includes('SEC'))?.id ?? secondDeptId,
  );
  const defaultCategory = categories?.[0]?.code ?? 'GENERAL_OPERATIONS';
  const securityCategory =
    categories?.find((c) => c.code.toUpperCase().includes('SECURITY'))?.code ?? defaultCategory;
  const financeCategory =
    categories?.find((c) => c.code.toUpperCase().includes('FINANC'))?.code ?? defaultCategory;

  if (presetName === 'trusted_employee') {
    return {
      subject: {
        clearanceRank: 4,
        departmentId: firstDeptId,
        employmentStatus: 'ACTIVE',
        projects: ['PROJECT_ALPHA'],
      },
      resource: {
        classificationRank: 3,
        departmentId: firstDeptId,
        category: securityCategory,
        status: 'ACTIVE',
        ownerId: '1',
      },
      environment: {
        currentTime: '14:00',
        ip: '192.168.1.100',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: 10,
      },
    };
  }
  if (presetName === 'remote_suspicious') {
    return {
      subject: {
        clearanceRank: 2,
        departmentId: firstDeptId,
        employmentStatus: 'ACTIVE',
        projects: [],
      },
      resource: {
        classificationRank: 4,
        departmentId: securityDeptId,
        category: securityCategory,
        status: 'ACTIVE',
        ownerId: '99',
      },
      environment: {
        currentTime: '23:45',
        ip: '203.0.113.10',
        trustedNetwork: false,
        deviceTrust: false,
        mfa: false,
        riskScore: 85,
      },
    };
  }
  return {
    subject: {
      clearanceRank: 3,
      departmentId: firstDeptId,
      employmentStatus: 'ACTIVE',
      projects: ['HR_REVAMP'],
    },
    resource: {
      classificationRank: 3,
      departmentId: financeDeptId,
      category: financeCategory,
      status: 'ACTIVE',
      ownerId: '5',
    },
    environment: {
      currentTime: '09:15',
      ip: '192.168.1.55',
      trustedNetwork: true,
      deviceTrust: true,
      mfa: true,
      riskScore: 15,
    },
  };
}
