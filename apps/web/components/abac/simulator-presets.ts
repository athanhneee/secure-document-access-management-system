import type { VisualObligation } from './abac-models';

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

export interface SimulationResult {
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

/**
 * Algorithm / Thuật toán: Khởi tạo Vector Ngữ Cảnh Đối Chứng An Ninh (Preset Security Context Initialization)
 * Mục đích: Tái lập nhanh 3 trạng thái kiểm thử điển hình (nhân sự tin cậy, truy cập từ xa rủi ro cao vượt cấp độ mật Bell-LaPadula, truy cập chéo phòng ban).
 */
export function buildSimulationPreset(presetName: SimulationPresetName): {
  subject: SimulationSubject;
  resource: SimulationResource;
  environment: SimulationEnvironment;
} {
  if (presetName === 'trusted_employee') {
    return {
      subject: {
        clearanceRank: 4,
        departmentId: 'IT_DEPT',
        employmentStatus: 'ACTIVE',
        projects: ['PROJECT_ALPHA'],
      },
      resource: {
        classificationRank: 3,
        departmentId: 'IT_DEPT',
        category: 'SECURITY',
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
        departmentId: 'HR_DEPT',
        employmentStatus: 'ACTIVE',
        projects: [],
      },
      resource: {
        classificationRank: 4,
        departmentId: 'SECURITY_DEPT',
        category: 'SECURITY',
        status: 'ACTIVE',
        ownerId: '99',
      },
      environment: {
        currentTime: '23:45',
        ip: '203.113.152.12',
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
      departmentId: 'HR_DEPT',
      employmentStatus: 'ACTIVE',
      projects: ['HR_REVAMP'],
    },
    resource: {
      classificationRank: 3,
      departmentId: 'FINANCE_DEPT',
      category: 'FINANCE',
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
