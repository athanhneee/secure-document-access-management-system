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

export const CLEARANCE_OPTIONS: AttributeOption[] = [
  { label: 'Cấp 1 - Không mật (UNCLASSIFIED)', value: 1 },
  { label: 'Cấp 2 - Mật (CONFIDENTIAL)', value: 2 },
  { label: 'Cấp 3 - Tối mật (SECRET)', value: 3 },
  { label: 'Cấp 4 - Tuyệt mật (TOP_SECRET)', value: 4 },
];

export const DEPARTMENT_OPTIONS: AttributeOption[] = [
  { label: 'Phòng An ninh Thông tin (SECURITY_DEPT)', value: 'SECURITY_DEPT' },
  { label: 'Phòng Công nghệ & Kỹ thuật (IT_DEPT)', value: 'IT_DEPT' },
  { label: 'Phòng Tài chính - Kế toán (FINANCE_DEPT)', value: 'FINANCE_DEPT' },
  { label: 'Phòng Pháp chế & Tuân thủ (LEGAL_DEPT)', value: 'LEGAL_DEPT' },
  { label: 'Phòng Nhân sự & Hành chính (HR_DEPT)', value: 'HR_DEPT' },
  { label: 'Ban Kiểm toán Độc lập (AUDIT_DEPT)', value: 'AUDIT_DEPT' },
  { label: 'Khối Nghiên cứu & Phát triển (RD_DEPT)', value: 'RD_DEPT' },
];

export const ATTRIBUTE_REGISTRY: Record<string, AttributeMetadata> = {
  // SUBJECT ATTRIBUTES
  'subject.clearanceRank': {
    key: 'subject.clearanceRank',
    label: 'Cấp bậc An ninh Nhân sự (Clearance Rank)',
    category: 'SUBJECT',
    type: 'NUMBER',
    description:
      'Cấp độ phân quyền an ninh tối đa của người dùng (1 = Unclassified, 4 = Top Secret)',
    supportedOperators: ['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'IN'],
    options: CLEARANCE_OPTIONS,
    defaultValue: 2,
  },
  'subject.departmentId': {
    key: 'subject.departmentId',
    label: 'Phòng ban Người dùng (Subject Department)',
    category: 'SUBJECT',
    type: 'STRING',
    description: 'Mã phòng ban trực thuộc hiện tại của nhân sự thao tác',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN', 'EXISTS'],
    options: DEPARTMENT_OPTIONS,
    defaultValue: 'IT_DEPT',
  },
  'subject.employmentStatus': {
    key: 'subject.employmentStatus',
    label: 'Trạng thái Nhân sự (Employment Status)',
    category: 'SUBJECT',
    type: 'STRING',
    description: 'Trạng thái công tác của người dùng trong hệ thống',
    supportedOperators: ['EQ', 'NEQ', 'IN'],
    options: [
      { label: 'Đang làm việc (ACTIVE)', value: 'ACTIVE' },
      { label: 'Đang thử việc (PROBATION)', value: 'PROBATION' },
      { label: 'Tạm đình chỉ (SUSPENDED)', value: 'SUSPENDED' },
    ],
    defaultValue: 'ACTIVE',
  },
  'subject.projects': {
    key: 'subject.projects',
    label: 'Dự án Phụ trách (Assigned Projects)',
    category: 'SUBJECT',
    type: 'STRING',
    description: 'Mã danh mục dự án mà nhân viên đang được điều động tham gia',
    supportedOperators: ['IN', 'NOT_IN', 'EXISTS'],
    defaultValue: ['PROJECT_ALPHA'],
  },

  // RESOURCE ATTRIBUTES
  'resource.classificationRank': {
    key: 'resource.classificationRank',
    label: 'Cấp độ Mật Tài liệu (Classification Rank)',
    category: 'RESOURCE',
    type: 'NUMBER',
    description: 'Mức độ bảo mật của tài liệu (1 = Không mật đến 4 = Tuyệt mật)',
    supportedOperators: ['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'IN'],
    options: CLEARANCE_OPTIONS,
    defaultValue: 3,
  },
  'resource.departmentId': {
    key: 'resource.departmentId',
    label: 'Phòng ban Sở hữu Tài liệu (Resource Department)',
    category: 'RESOURCE',
    type: 'STRING',
    description: 'Đơn vị ban hành và nắm giữ chủ quyền quản lý tài liệu',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
    options: DEPARTMENT_OPTIONS,
    defaultValue: 'FINANCE_DEPT',
  },
  'resource.category': {
    key: 'resource.category',
    label: 'Danh mục Tài liệu (Resource Category)',
    category: 'RESOURCE',
    type: 'STRING',
    description: 'Phân loại nghiệp vụ của tệp tài liệu',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
    options: [
      { label: 'Tài liệu Tài chính (FINANCE)', value: 'FINANCE' },
      { label: 'Tài liệu Pháp chế & Hợp đồng (LEGAL)', value: 'LEGAL' },
      { label: 'Hồ sơ Nhân sự (HR)', value: 'HR' },
      { label: 'Chính sách An toàn Thông tin (SECURITY)', value: 'SECURITY' },
      { label: 'Nghiên cứu & Thiết kế (R_AND_D)', value: 'R_AND_D' },
      { label: 'Tài liệu Nghiệp vụ Chung (GENERAL)', value: 'GENERAL' },
    ],
    defaultValue: 'FINANCE',
  },
  'resource.status': {
    key: 'resource.status',
    label: 'Trạng thái Tài liệu (Resource Status)',
    category: 'RESOURCE',
    type: 'STRING',
    description: 'Vòng đời hiện tại của tài liệu trong hệ thống',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
    options: [
      { label: 'Bản thảo (DRAFT)', value: 'DRAFT' },
      { label: 'Đang ban hành hiệu lực (ACTIVE)', value: 'ACTIVE' },
      { label: 'Lưu trữ lịch sử (ARCHIVED)', value: 'ARCHIVED' },
      { label: 'Đã thu hồi hủy bỏ (REVOKED)', value: 'REVOKED' },
    ],
    defaultValue: 'ACTIVE',
  },
  'resource.ownerId': {
    key: 'resource.ownerId',
    label: 'Mã Định danh Người tạo (Owner ID)',
    category: 'RESOURCE',
    type: 'STRING',
    description: 'ID tài khoản tác giả tải lên hoặc khởi tạo tài liệu',
    supportedOperators: ['EQ', 'NEQ', 'EXISTS'],
    defaultValue: '1',
  },

  // ENVIRONMENT ATTRIBUTES
  'environment.trustedNetwork': {
    key: 'environment.trustedNetwork',
    label: 'Mạng Tin cậy Cơ quan (Trusted Network)',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    description: 'Truy cập xuất phát từ dải IP nội bộ hoặc VPN chuyên dụng của tổ chức',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Nằm trong mạng nội bộ (true)', value: true },
      { label: 'Từ mạng Internet công cộng bên ngoài (false)', value: false },
    ],
    defaultValue: true,
  },
  'environment.deviceTrust': {
    key: 'environment.deviceTrust',
    label: 'Thiết bị Hợp chuẩn MDM (Device Trust)',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    description: 'Máy trạm có chứng chỉ quản trị an ninh thiết bị của cơ quan',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Thiết bị tin cậy đã kiểm định (true)', value: true },
      { label: 'Thiết bị cá nhân BYOD chưa kiểm định (false)', value: false },
    ],
    defaultValue: true,
  },
  'environment.mfa': {
    key: 'environment.mfa',
    label: 'Xác thực Đa yếu tố Đang bật (MFA Active)',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    description: 'Phiên đăng nhập đã hoàn thành xác thực FIDO2 / YubiKey / TOTP',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Đã hoàn thành bước xác thực MFA (true)', value: true },
      { label: 'Chỉ đăng nhập mật khẩu đơn (false)', value: false },
    ],
    defaultValue: true,
  },
  'environment.riskScore': {
    key: 'environment.riskScore',
    label: 'Điểm Rủi ro Hành vi (Risk Score: 0 - 100)',
    category: 'ENVIRONMENT',
    type: 'NUMBER',
    description:
      'Điểm đánh giá rủi ro phiên theo Machine Learning (0 = Tuyệt đối an toàn, 100 = Nguy cơ cao)',
    supportedOperators: ['LTE', 'GTE', 'BETWEEN', 'EQ'],
    defaultValue: 30,
  },
  'environment.currentTime': {
    key: 'environment.currentTime',
    label: 'Khung giờ Truy cập Cho phép (Time Window)',
    category: 'ENVIRONMENT',
    type: 'DATE',
    description: 'Ràng buộc giờ hành chính hoặc khoảng thời gian hợp lệ trong ngày',
    supportedOperators: ['TIME_BETWEEN'],
    defaultValue: {
      start: '08:00',
      end: '17:30',
      timeZone: 'Asia/Ho_Chi_Minh',
    },
  },
  'environment.ip': {
    key: 'environment.ip',
    label: 'Dải Địa chỉ IP Nguồn (Source IP / CIDR)',
    category: 'ENVIRONMENT',
    type: 'IP',
    description: 'Khớp dải mạng IP theo ký hiệu CIDR (VD: 192.168.1.0/24 hoặc 10.0.0.0/8)',
    supportedOperators: ['CIDR_MATCH', 'EQ', 'NEQ'],
    defaultValue: '192.168.1.0/24',
  },
};

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
