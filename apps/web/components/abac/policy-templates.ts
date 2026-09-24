import type { VisualPolicyRule } from './abac-models';

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
    name: 'Mạng nội bộ trong giờ làm việc (Office Hours & Intranet)',
    badge: 'Phổ biến',
    summary:
      'Chỉ cho phép truy cập tài liệu từ mạng nội bộ cơ quan trong khung giờ 08:00 - 17:30 và có mức rủi ro phiên thấp.',
    rule: {
      id: 'rule-tpl-office-hours',
      code: 'POL_OFFICE_HOURS_INTRANET',
      name: 'Chính sách Giờ Hành chính & Mạng Nội bộ',
      description:
        'Chỉ nhân viên kết nối từ mạng tin cậy trong giờ làm việc mới được truy cập tài liệu.',
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
    name: 'Bảo vệ tài liệu Tuyệt mật (Top Secret + FIDO2 MFA)',
    badge: 'An ninh tối mật',
    summary:
      'Yêu cầu Clearance Cấp 4 (Tuyệt mật), xác thực FIDO2/YubiKey, thiết bị đạt chuẩn MDM và cấm tải về (chỉ xem trực tuyến kèm Watermark).',
    rule: {
      id: 'rule-tpl-top-secret',
      code: 'POL_TOP_SECRET_HARDENED',
      name: 'Kiểm soát Truy cập Tài liệu Tuyệt mật Cấp 4',
      description:
        'Ràng buộc tối nghiêm ngặt với tài liệu Tuyệt mật: bắt buộc Clearance Cấp 4, FIDO2 MFA và cấm tuyệt đối tải file ngoại tuyến.',
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
    name: 'Cách ly phòng ban nghiêm ngặt (Strict Department Boundary)',
    badge: 'Chặn rò rỉ chéo',
    summary:
      'Từ chối (DENY) mọi yêu cầu truy cập tài liệu Tài chính - Kế toán nếu người dùng không thuộc phòng ban này.',
    rule: {
      id: 'rule-tpl-dept-iso',
      code: 'POL_FINANCE_DEPT_ISOLATION',
      name: 'Cách ly Ngăn chặn Truy cập Chéo Phòng ban Tài chính',
      description:
        'Nghiêm cấm người dùng ngoài phòng ban can thiệp hoặc xem các sổ sách tài chính nội bộ.',
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
    name: 'Chặn tải về trên mạng ngoài (Untrusted Network Download Block)',
    badge: 'Chống thất thoát dữ liệu',
    summary:
      'Chặn quyền DOWNLOAD tài liệu khi người dùng truy cập từ mạng công cộng không tin cậy.',
    rule: {
      id: 'rule-tpl-untrusted-dl',
      code: 'POL_BLOCK_UNTRUSTED_DOWNLOAD',
      name: 'Chặn Tải về từ Mạng Bên ngoài',
      description:
        'Người dùng từ xa chỉ có thể xem trực tuyến với Watermark, không được phép lưu trữ bản sao về máy trạm cá nhân.',
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
    name: 'Đặc quyền Kiểm toán viên Độc lập (Auditor Read-only Exemption)',
    badge: 'Kiểm toán & Tuân thủ',
    summary:
      'Ban Kiểm toán có thể xem toàn bộ tài liệu đã ban hành nếu có MFA kích hoạt, nhưng bị cấm tải xuống.',
    rule: {
      id: 'rule-tpl-auditor',
      code: 'POL_AUDITOR_READ_ONLY_ACCESS',
      name: 'Quyền Tra cứu Dành cho Ban Kiểm toán Độc lập',
      description:
        'Cho phép kiểm toán viên tra cứu đối soát tài liệu với cam kết nghĩa vụ đóng dấu thủy ấn và cấm tải file.',
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
