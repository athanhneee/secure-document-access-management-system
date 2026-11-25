/**
 * Thuật toán & Cấu hình: Từ Điển Siêu Dữ Liệu Thuộc Tính ABAC Động Từ CSDL (`abac-presets`)
 * Mục đích: Khai báo miền giá trị hợp lệ, kiểu tĩnh và toán tử cho phép đối với 15 thuộc tính Subject/Resource/Environment,
 * đồng thời hợp nhất danh sách phòng ban (`id` dạng chuỗi khớp PEP) và danh mục tài liệu nghiệp vụ thực tế từ CSDL.
 */
import type { AttributeMetadata, AttributeOption } from './abac-models';

export interface DynamicDepartmentOption {
  id: string;
  code: string;
  name: string;
}

export interface DynamicCategoryOption {
  id?: string;
  code: string;
  name: string;
}

// CONFLICT-RESOLVED: Đồng bộ danh mục cấp bậc độ mật ABAC (1 = INTERNAL .. 4 = TOP_SECRET) khớp với CSDL và ClassificationRank trong @sda/contracts.
export const CLEARANCE_OPTIONS: AttributeOption[] = [
  { label: 'Cấp 1 — Nội bộ', value: 1 },
  { label: 'Cấp 2 — Mật', value: 2 },
  { label: 'Cấp 3 — Tối mật', value: 3 },
  { label: 'Cấp 4 — Tuyệt mật', value: 4 },
];

export const DEPARTMENT_OPTIONS: AttributeOption[] = [
  { label: 'Khối Văn phòng & Quản trị (EXEC_OFFICE)', value: '1' },
  { label: 'Phòng An toàn Thông tin (INFOSEC_SOC)', value: '2' },
  { label: 'Ban Pháp chế & Tuân thủ (LEGAL_COMPLIANCE)', value: '3' },
  { label: 'Khối Tài chính & Kho bạc (FINANCE_TREASURY)', value: '4' },
  { label: 'Khối Công nghệ & Kỹ thuật (ENGINEERING_RD)', value: '5' },
];

export const CATEGORY_OPTIONS: AttributeOption[] = [
  { label: 'Tài liệu vận hành chung (GENERAL_OPERATIONS)', value: 'GENERAL_OPERATIONS' },
  { label: 'Vận hành an toàn thông tin (SECURITY_OPERATIONS)', value: 'SECURITY_OPERATIONS' },
  { label: 'Hợp đồng & pháp chế (LEGAL_CONTRACTS)', value: 'LEGAL_CONTRACTS' },
  { label: 'Báo cáo tài chính (FINANCIAL_REPORTS)', value: 'FINANCIAL_REPORTS' },
];

export const EMPLOYMENT_STATUS_OPTIONS: AttributeOption[] = [
  { label: 'Tài khoản đang hoạt động (ACTIVE)', value: 'ACTIVE' },
  { label: 'Nhân sự chính thức (ACTIVE_STAFF)', value: 'ACTIVE_STAFF' },
  { label: 'Cộng tác viên / Nhà thầu (CONTRACTOR)', value: 'CONTRACTOR' },
  { label: 'Tạm đình chỉ công tác (SUSPENDED)', value: 'SUSPENDED' },
];

export const ATTRIBUTE_REGISTRY: Record<string, AttributeMetadata> = {
  'subject.clearanceRank': {
    key: 'subject.clearanceRank',
    label: 'Cấp thẩm quyền bảo mật của người dùng',
    category: 'SUBJECT',
    type: 'NUMBER',
    options: CLEARANCE_OPTIONS,
    defaultValue: 2,
    description:
      'Cấp thẩm quyền bảo mật tối đa của người dùng (0 = Không mật, 1 = Nội bộ đến 4 = Tuyệt mật).',
    supportedOperators: ['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'IN'],
  },
  'subject.departmentId': {
    key: 'subject.departmentId',
    label: 'Phòng ban của người dùng',
    category: 'SUBJECT',
    type: 'STRING',
    options: DEPARTMENT_OPTIONS,
    defaultValue: '1',
    description:
      'Phòng ban trực thuộc hiện tại của người dùng thực hiện truy cập (khớp ID phòng ban CSDL).',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN', 'EXISTS'],
  },
  'subject.employmentStatus': {
    key: 'subject.employmentStatus',
    label: 'Trạng thái công tác',
    category: 'SUBJECT',
    type: 'STRING',
    defaultValue: 'ACTIVE',
    description:
      'Trạng thái làm việc của người dùng trong tổ chức (thuộc tính EMPLOYMENT_STATUS hoặc trạng thái tài khoản).',
    supportedOperators: ['EQ', 'NEQ', 'IN'],
    options: EMPLOYMENT_STATUS_OPTIONS,
  },
  'subject.projects': {
    key: 'subject.projects',
    label: 'Dự án phụ trách',
    category: 'SUBJECT',
    type: 'STRING',
    defaultValue: ['PROJECT_ALPHA'],
    description: 'Danh mục dự án mà nhân sự đang được phân công tham gia.',
    supportedOperators: ['IN', 'NOT_IN', 'EXISTS'],
  },
  'resource.classificationRank': {
    key: 'resource.classificationRank',
    label: 'Mức độ mật tài liệu',
    category: 'RESOURCE',
    type: 'NUMBER',
    options: CLEARANCE_OPTIONS,
    defaultValue: 3,
    description: 'Mức độ mật của tài liệu (0 = Không mật, 1 = Nội bộ đến 4 = Tuyệt mật).',
    supportedOperators: ['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'IN'],
  },
  'resource.departmentId': {
    key: 'resource.departmentId',
    label: 'Phòng ban sở hữu tài liệu',
    category: 'RESOURCE',
    type: 'STRING',
    options: DEPARTMENT_OPTIONS,
    defaultValue: '4',
    description: 'Đơn vị ban hành và quản lý tài liệu (khớp ID phòng ban CSDL).',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
  },
  'resource.category': {
    key: 'resource.category',
    label: 'Danh mục tài liệu',
    category: 'RESOURCE',
    type: 'STRING',
    defaultValue: 'FINANCIAL_REPORTS',
    description: 'Phân loại danh mục nghiệp vụ thực tế của tài liệu trong hệ thống.',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
    options: CATEGORY_OPTIONS,
  },
  'resource.status': {
    key: 'resource.status',
    label: 'Trạng thái tài liệu',
    category: 'RESOURCE',
    type: 'STRING',
    defaultValue: 'ACTIVE',
    description: 'Trạng thái vòng đời hiện tại của tài liệu trong hệ thống.',
    supportedOperators: ['EQ', 'NEQ', 'IN', 'NOT_IN'],
    options: [
      { label: 'Bản nháp (DRAFT)', value: 'DRAFT' },
      { label: 'Đang hiệu lực (ACTIVE)', value: 'ACTIVE' },
      { label: 'Đã lưu trữ (ARCHIVED)', value: 'ARCHIVED' },
      { label: 'Đã xóa (DELETED)', value: 'DELETED' },
    ],
  },
  'resource.ownerId': {
    key: 'resource.ownerId',
    label: 'Mã tài khoản chủ sở hữu',
    category: 'RESOURCE',
    type: 'STRING',
    defaultValue: '1',
    description: 'Mã tài khoản của người tải lên hoặc quản lý tài liệu.',
    supportedOperators: ['EQ', 'NEQ', 'EXISTS'],
  },
  'environment.trustedNetwork': {
    key: 'environment.trustedNetwork',
    label: 'Mạng nội bộ tin cậy',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    defaultValue: true,
    description: 'Truy cập xuất phát từ dải IP nội bộ hoặc VPN của tổ chức.',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Trong mạng nội bộ tin cậy', value: true },
      { label: 'Ngoài mạng nội bộ', value: false },
    ],
  },
  'environment.deviceTrust': {
    key: 'environment.deviceTrust',
    label: 'Thiết bị được quản trị tin cậy',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    defaultValue: true,
    description: 'Thiết bị đáp ứng tiêu chuẩn quản trị bảo mật của tổ chức.',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Thiết bị tin cậy đã kiểm định', value: true },
      { label: 'Thiết bị chưa kiểm định', value: false },
    ],
  },
  'environment.mfa': {
    key: 'environment.mfa',
    label: 'Xác thực đa yếu tố (MFA)',
    category: 'ENVIRONMENT',
    type: 'BOOLEAN',
    defaultValue: true,
    description:
      'Phiên đăng nhập đã hoàn tất xác thực đa yếu tố (khóa bảo mật, Passkey hoặc mã OTP).',
    supportedOperators: ['EQ'],
    options: [
      { label: 'Đã xác thực MFA', value: true },
      { label: 'Chưa xác thực MFA', value: false },
    ],
  },
  'environment.riskScore': {
    key: 'environment.riskScore',
    label: 'Điểm rủi ro phiên (0–100)',
    category: 'ENVIRONMENT',
    type: 'NUMBER',
    defaultValue: 30,
    description: 'Điểm đánh giá mức độ rủi ro của phiên làm việc (0 = An toàn, 100 = Nguy cơ cao).',
    supportedOperators: ['LTE', 'GTE', 'BETWEEN', 'EQ'],
  },
  'environment.currentTime': {
    key: 'environment.currentTime',
    label: 'Khung giờ truy cập cho phép',
    category: 'ENVIRONMENT',
    type: 'DATE',
    description: 'Giới hạn giờ làm việc hoặc khung thời gian hợp lệ trong ngày.',
    supportedOperators: ['TIME_BETWEEN'],
    defaultValue: { start: '08:00', end: '17:30', timeZone: 'Asia/Ho_Chi_Minh' },
  },
  'environment.ip': {
    key: 'environment.ip',
    label: 'Dải địa chỉ IP nguồn',
    category: 'ENVIRONMENT',
    type: 'IP',
    defaultValue: '192.168.1.0/24',
    description: 'Khớp dải địa chỉ IP theo ký hiệu CIDR (ví dụ: 192.168.1.0/24 hoặc 10.0.0.0/8).',
    supportedOperators: ['CIDR_MATCH', 'EQ', 'NEQ'],
  },
};

/**
 * Thuật toán: Ánh Xạ Danh Sách Phòng Ban Thực Tế Thành Lựa Chọn ABAC Có Giá Trị Khớp PEP (`buildDepartmentSelectOptions`)
 */
export function buildDepartmentSelectOptions(
  departments?: readonly DynamicDepartmentOption[],
): AttributeOption[] {
  if (!departments || departments.length === 0) return DEPARTMENT_OPTIONS;
  return departments.map((d) => ({
    label: `${d.name} (${d.code})`,
    value: String(d.id),
  }));
}

/**
 * Thuật toán: Ánh Xạ Danh Mục Tài Liệu Nghiệp Vụ Thực Tế Thành Lựa Chọn ABAC (`buildCategorySelectOptions`)
 */
export function buildCategorySelectOptions(
  categories?: readonly DynamicCategoryOption[],
): AttributeOption[] {
  if (!categories || categories.length === 0) return CATEGORY_OPTIONS;
  return categories.map((c) => ({
    label: `${c.name} (${c.code})`,
    value: c.code,
  }));
}

/**
 * Thuật toán: Hợp Nhất Từ Điển Thuộc Tính ABAC Với Dữ Liệu Phòng Ban & Danh Mục Động Từ CSDL (`buildDynamicAttributeRegistry`)
 * Mục đích: Đảm bảo mọi phòng ban hoặc danh mục tài liệu vừa thêm từ Quản trị lập tức xuất hiện trong Trình dựng chính sách ABAC với đúng định danh số mà PEP đối chiếu lúc chạy.
 */
export function buildDynamicAttributeRegistry(
  departments?: readonly DynamicDepartmentOption[],
  categories?: readonly DynamicCategoryOption[],
): Record<string, AttributeMetadata> {
  const deptOptions = buildDepartmentSelectOptions(departments);
  const categoryOptions = buildCategorySelectOptions(categories);
  const defaultDeptValue = String(deptOptions[0]?.value ?? '1');
  const defaultCategoryValue = String(categoryOptions[0]?.value ?? 'GENERAL_OPERATIONS');

  return {
    ...ATTRIBUTE_REGISTRY,
    'subject.departmentId': {
      ...ATTRIBUTE_REGISTRY['subject.departmentId']!,
      options: deptOptions,
      defaultValue: defaultDeptValue,
    },
    'resource.departmentId': {
      ...ATTRIBUTE_REGISTRY['resource.departmentId']!,
      options: deptOptions,
      defaultValue: defaultDeptValue,
    },
    'resource.category': {
      ...ATTRIBUTE_REGISTRY['resource.category']!,
      options: categoryOptions,
      defaultValue: defaultCategoryValue,
    },
  };
}
