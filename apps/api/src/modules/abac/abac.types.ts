export const POLICY_OPERATORS = [
  'EQ',
  'NEQ',
  'IN',
  'NOT_IN',
  'GTE',
  'LTE',
  'BETWEEN',
  'CIDR_MATCH',
  'TIME_BETWEEN',
  'EXISTS',
] as const;

export type PolicyOperator = (typeof POLICY_OPERATORS)[number];
export type AttributeType = 'STRING' | 'NUMBER' | 'BOOLEAN' | 'DATE' | 'IP';
export type PolicyEffect = 'PERMIT' | 'DENY';
export type PolicyDecision = 'PERMIT' | 'DENY';

export type PolicyObligation =
  | { type: 'REQUIRE_WATERMARK' }
  | { type: 'REQUIRE_MFA' }
  | { type: 'MAX_SESSION_MINUTES'; minutes: number }
  | { type: 'FORBID_DOWNLOAD' }
  | { type: 'NO_CACHE' };

export interface TimeWindow {
  start: string;
  end: string;
  timeZone: string;
}

export type ExpectedValue =
  string | number | boolean | Array<string | number | boolean> | TimeWindow;

export interface PolicyCondition {
  id: string;
  attribute: string;
  operator: PolicyOperator;
  expected: ExpectedValue;
}

export interface PolicyConditionGroup {
  id: number;
  conditions: PolicyCondition[];
}

export interface CompiledPolicyRule {
  id: string;
  code: string;
  effect: PolicyEffect;
  priority: number;
  targetResource: 'DOCUMENT';
  targetAction: 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE' | null;
  combiningAlgorithm: 'DENY_OVERRIDES';
  validFrom: string;
  validTo: string | null;
  groups: PolicyConditionGroup[];
  obligations: PolicyObligation[];
}

export interface CompiledPolicy {
  version: string;
  requiredAttributes: string[];
  rules: CompiledPolicyRule[];
}

export interface SubjectAttributes {
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
}

export interface ResourceAttributes {
  classificationRank: number | null;
  ownerId: string | null;
  departmentId: string | null;
  category: string | null;
  status: string | null;
}

export interface EnvironmentAttributes {
  currentTime: string;
  ip: string | null;
  trustedNetwork: boolean;
  deviceTrust: boolean;
  mfa: boolean;
  riskScore: number;
}

export interface PolicyEvaluationInput {
  resourceType: 'DOCUMENT';
  action: 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE';
  subject: SubjectAttributes;
  resource: ResourceAttributes;
  environment: EnvironmentAttributes;
}

export type PdpReasonCode =
  | 'POLICY_PERMIT'
  | 'DEFAULT_DENY'
  | 'EXPLICIT_DENY'
  | 'MISSING_REQUIRED_ATTRIBUTE'
  | 'INSUFFICIENT_CLEARANCE'
  | 'INVALID_POLICY';

export interface PdpResult {
  decision: PolicyDecision;
  reasonCode: PdpReasonCode;
  matchedRuleIds: string[];
  obligations: PolicyObligation[];
  policyVersion: string;
}

export interface AttributeDescriptor {
  key: string;
  type: AttributeType;
  required: boolean;
}

export const VALID_SIMPLE_OBLIGATION_TYPES = [
  'REQUIRE_WATERMARK',
  'REQUIRE_MFA',
  'FORBID_DOWNLOAD',
  'NO_CACHE',
] as const;

export const MAX_SESSION_MINUTES_FLOOR = 1;
export const MAX_SESSION_MINUTES_CEILING = 1440;

export interface PolicyValidationIssue {
  code:
    | 'UNKNOWN_ATTRIBUTE'
    | 'UNSUPPORTED_OPERATOR'
    | 'INVALID_EXPECTED_VALUE'
    | 'EMPTY_GROUP'
    | 'UNREACHABLE_RULE'
    | 'INVALID_OBLIGATION'
    | 'INVALID_COMBINING_ALGORITHM';
  ruleId: string;
  conditionId?: string;
  message?: string;
}
