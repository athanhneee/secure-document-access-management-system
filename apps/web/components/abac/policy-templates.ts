import type { VisualPolicyRule } from './abac-models';

/**
 * Thuật toán: Khởi tạo Cây Cú Pháp Trừu Tượng (AST) Dạng Chuẩn Tuyển (DNF) cho Mẫu Chính Sách ABAC
 * Mục đích: Cung cấp bộ quy tắc mẫu chuẩn hóa theo các mô hình an ninh kinh điển để nạp nhanh vào trình biên tập trực quan mà không cần dựng tay từng nút điều kiện.
 * Cơ chế hoạt động:
 *   - Biểu diễn sẵn các cấu trúc DNF cho 5 kịch bản trọng yếu: Ràng buộc giờ hành chính & mạng nội bộ, Bảo vệ tài liệu Tuyệt mật (Bell-LaPadula Cấp 4 + FIDO2 MFA), Cách ly phòng ban nghiêm ngặt (Strict Department Isolation), Chặn tải về từ mạng không tin cậy, và Đặc quyền chỉ đọc của Kiểm toán viên (Separation of Duties).
 *   - Gắn kèm tập nghĩa vụ bắt buộc (`obligations`) và luật kết hợp ưu tiên từ chối (`DENY_OVERRIDES`).
 */
export interface PolicyTemplate {
  id: string;
  name: string;
  badge: string;
  summary: string;
  rule: VisualPolicyRule;
}

export const PRESET_POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'tpl-office-hours',
    name: 'Mạng nội bộ trong giờ làm việc',
    badge: 'Phổ biến',
    summary:
      'Chỉ cho phép truy cập tài liệu từ mạng nội bộ tổ chức trong khung giờ 08:00 – 17:30 và có mức rủi ro phiên thấp.',
    rule: {
      id: 'rule-tpl-office-hours',
      code: 'POL_OFFICE_HOURS_INTRANET',
      name: 'Chính sách giờ làm việc và mạng nội bộ',
      description:
        'Chỉ nhân sự kết nối từ mạng tin cậy trong giờ làm việc mới được truy cập tài liệu.',
      effect: 'PERMIT',
      priority: 10,
      targetResource: 'DOCUMENT',
      targetAction: 'ALL',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'cond-101',
              attribute: 'environment.trustedNetwork',
              operator: 'EQ',
              expected: true,
            },
            {
              id: 'cond-102',
              attribute: 'environment.currentTime',
              operator: 'TIME_BETWEEN',
              expected: {
                start: '08:00',
                end: '17:30',
                timeZone: 'Asia/Ho_Chi_Minh',
              },
            },
            {
              id: 'cond-103',
              attribute: 'environment.riskScore',
              operator: 'LTE',
              expected: 35,
            },
          ],
        },
      ],
      obligations: [{ type: 'REQUIRE_WATERMARK' }],
    },
  },
  {
    id: 'tpl-top-secret-mfa',
    name: 'Bảo vệ tài liệu Tuyệt mật (kèm MFA)',
    badge: 'Bảo mật cao',
    summary:
      'Yêu cầu cấp thẩm quyền Tuyệt mật (Cấp 4), đã xác thực MFA trên thiết bị tin cậy và cấm tải về (chỉ xem trực tuyến kèm watermark bảo mật).',
    rule: {
      id: 'rule-tpl-top-secret',
      code: 'POL_TOP_SECRET_HARDENED',
      name: 'Kiểm soát truy cập tài liệu Tuyệt mật (Cấp 4)',
      description:
        'Ràng buộc nghiêm ngặt với tài liệu Tuyệt mật: yêu cầu thẩm quyền Cấp 4, xác thực MFA và cấm tải về tệp gốc.',
      effect: 'PERMIT',
      priority: 5,
      targetResource: 'DOCUMENT',
      targetAction: 'VIEW',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'cond-201',
              attribute: 'resource.classificationRank',
              operator: 'GTE',
              expected: 4,
            },
            {
              id: 'cond-202',
              attribute: 'subject.clearanceRank',
              operator: 'GTE',
              expected: 4,
            },
            {
              id: 'cond-203',
              attribute: 'environment.mfa',
              operator: 'EQ',
              expected: true,
            },
            {
              id: 'cond-204',
              attribute: 'environment.deviceTrust',
              operator: 'EQ',
              expected: true,
            },
          ],
        },
      ],
      obligations: [
        { type: 'REQUIRE_WATERMARK' },
        { type: 'REQUIRE_MFA' },
        { type: 'FORBID_DOWNLOAD' },
        { type: 'MAX_SESSION_MINUTES', minutes: 20 },
      ],
    },
  },
  {
    id: 'tpl-dept-isolation',
    name: 'Cách ly phòng ban nghiêm ngặt',
    badge: 'Chặn rò rỉ chéo',
    summary:
      'Từ chối mọi yêu cầu truy cập tài liệu Tài chính – Kế toán nếu người dùng không thuộc phòng ban này.',
    rule: {
      id: 'rule-tpl-dept-iso',
      code: 'POL_FINANCE_DEPT_ISOLATION',
      name: 'Cách ly truy cập chéo Phòng Tài chính',
      description: 'Ngăn người dùng ngoài phòng ban xem hoặc thao tác tài liệu tài chính nội bộ.',
      effect: 'DENY',
      priority: 1,
      targetResource: 'DOCUMENT',
      targetAction: 'ALL',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'cond-301',
              attribute: 'resource.departmentId',
              operator: 'EQ',
              expected: 'FINANCE_DEPT',
            },
            {
              id: 'cond-302',
              attribute: 'subject.departmentId',
              operator: 'NEQ',
              expected: 'FINANCE_DEPT',
            },
          ],
        },
      ],
      obligations: [{ type: 'NO_CACHE' }],
    },
  },
  {
    id: 'tpl-untrusted-download-block',
    name: 'Chặn tải về từ mạng bên ngoài',
    badge: 'Chống thất thoát dữ liệu',
    summary:
      'Chặn thao tác tải về tài liệu khi người dùng truy cập từ mạng công cộng không tin cậy.',
    rule: {
      id: 'rule-tpl-untrusted-dl',
      code: 'POL_BLOCK_UNTRUSTED_DOWNLOAD',
      name: 'Chặn tải về từ mạng bên ngoài',
      description:
        'Người dùng từ xa chỉ được xem trực tuyến kèm watermark bảo mật, không được lưu bản sao về thiết bị cá nhân.',
      effect: 'DENY',
      priority: 2,
      targetResource: 'DOCUMENT',
      targetAction: 'DOWNLOAD',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'cond-401',
              attribute: 'environment.trustedNetwork',
              operator: 'EQ',
              expected: false,
            },
          ],
        },
      ],
      obligations: [{ type: 'FORBID_DOWNLOAD' }],
    },
  },
  {
    id: 'tpl-auditor-read-only',
    name: 'Quyền chỉ đọc cho Kiểm toán viên độc lập',
    badge: 'Kiểm toán & Tuân thủ',
    summary:
      'Kiểm toán viên độc lập được xem tài liệu đã ban hành khi đã xác thực MFA, nhưng không được tải về.',
    rule: {
      id: 'rule-tpl-auditor',
      code: 'POL_AUDITOR_READ_ONLY_ACCESS',
      name: 'Quyền tra cứu cho Kiểm toán viên độc lập',
      description:
        'Cho phép kiểm toán viên tra cứu đối soát tài liệu kèm watermark bảo mật và cấm tải về.',
      effect: 'PERMIT',
      priority: 8,
      targetResource: 'DOCUMENT',
      targetAction: 'VIEW',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [
        {
          id: 1,
          conditions: [
            {
              id: 'cond-501',
              attribute: 'subject.departmentId',
              operator: 'EQ',
              expected: 'AUDIT_DEPT',
            },
            {
              id: 'cond-502',
              attribute: 'resource.status',
              operator: 'IN',
              expected: ['ACTIVE', 'ARCHIVED'],
            },
            {
              id: 'cond-503',
              attribute: 'environment.mfa',
              operator: 'EQ',
              expected: true,
            },
          ],
        },
      ],
      obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'FORBID_DOWNLOAD' }],
    },
  },
];
