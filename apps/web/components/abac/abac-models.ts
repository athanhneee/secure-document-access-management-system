/**
 * Thuật toán & Mô hình dữ liệu: Biểu diễn Dạng Chuẩn Tuyển ABAC (Disjunctive Normal Form - DNF) & Lưới Độ Mật Bell-LaPadula
 * Mục đích: Định nghĩa hệ thống kiểu tĩnh, tập toán tử vị từ, nghĩa vụ thực thi (Obligations) và từ điển siêu dữ liệu thuộc tính cho trình biên tập & giả lập chính sách ABAC.
 * Cơ chế hoạt động:
 *   - Cấu trúc hóa quy tắc chính sách theo chuẩn XACML / NIST SP 800-162 dưới dạng tuyển (OR) của các nhóm điều kiện liên hội (AND).
 *   - Mô hình hóa thang bậc an ninh (Clearance Rank & Classification Rank từ 1 đến 4) phục vụ kiểm tra bất biến thống trị độ mật.
 *   - Ràng buộc danh sách toán tử hợp lệ theo từng miền kiểu dữ liệu (STRING, NUMBER, BOOLEAN, DATE, IP) để ngăn chặn biểu thức sai kiểu ngay từ giao diện.
 */
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
export type TargetAction = 'ALL' | 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE';

export interface TimeWindow {
  start: string;
  end: string;
  timeZone: string;
}

export type ExpectedValue =
  string | number | boolean | Array<string | number | boolean> | TimeWindow;

export interface VisualCondition {
  id: string;
  attribute: string;
  operator: PolicyOperator;
  expected: ExpectedValue;
}

export interface VisualConditionGroup {
  id: number;
  conditions: VisualCondition[];
}

export type VisualObligation =
  | { type: 'REQUIRE_WATERMARK' }
  | { type: 'REQUIRE_MFA' }
  | { type: 'MAX_SESSION_MINUTES'; minutes: number }
  | { type: 'FORBID_DOWNLOAD' }
  | { type: 'NO_CACHE' };

export interface VisualPolicyRule {
  id: string;
  code: string;
  name: string;
  description: string;
  effect: PolicyEffect;
  priority: number;
  targetResource: 'DOCUMENT';
  targetAction: TargetAction;
  combiningAlgorithm: 'DENY_OVERRIDES';
  validFrom?: string;
  validTo?: string | null;
  groups: VisualConditionGroup[];
  obligations: VisualObligation[];
}

export type AttributeCategory = 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT';

export interface AttributeOption {
  label: string;
  value: string | number | boolean;
}

export interface AttributeMetadata {
  key: string;
  label: string;
  category: AttributeCategory;
  type: AttributeType;
  description: string;
  supportedOperators: PolicyOperator[];
  options?: AttributeOption[];
  defaultValue: ExpectedValue;
}

export const OPERATOR_LABELS: Record<PolicyOperator, string> = {
  EQ: 'Bằng (=)',
  NEQ: 'Không bằng (≠)',
  IN: 'Thuộc danh sách (IN)',
  NOT_IN: 'Không thuộc (NOT IN)',
  GTE: 'Lớn hơn hoặc bằng (≥)',
  LTE: 'Nhỏ hơn hoặc bằng (≤)',
  BETWEEN: 'Nằm trong khoảng (BETWEEN)',
  CIDR_MATCH: 'Khớp dải IP (CIDR)',
  TIME_BETWEEN: 'Trong khung giờ (TIME)',
  EXISTS: 'Tồn tại giá trị (EXISTS)',
};

export { CLEARANCE_OPTIONS, DEPARTMENT_OPTIONS, ATTRIBUTE_REGISTRY } from './abac-presets';
