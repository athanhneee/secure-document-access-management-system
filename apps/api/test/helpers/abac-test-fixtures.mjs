/**
 * Algorithm: 32-Bit Linear Congruential Generator (Numerical Recipes LCG)
 * Description: Produces a deterministic pseudo-random unsigned 32-bit integer stream from an
 *              initial seed using recurrence relation `X_{n+1} = (1664525 * X_n + 1013904223) mod 2^32`
 *              via unsigned right-shift coercion (`>>> 0`) for reproducible ABAC property fuzzing.
 * Time Complexity: O(1) per generated sample.
 * Space Complexity: O(1) closure state.
 */
/**
 * Thuật toán: Bộ Sinh Số Giả ngẫu nhiên Đồng dư Tuyến tính 32-bit (`seededRandom` — Numerical Recipes LCG)
 * Mục đích: Tạo chuỗi số nguyên không dấu 32-bit tất định từ hạt giống `seed` cố định để kiểm thử bất biến dựa trên thuộc tính (Property-Based Testing) có thể tái lập 100%.
 * Cơ chế hoạt động:
 *   - Áp dụng công thức truy hồi đồng dư tuyến tính `X_{n+1} = (a * X_n + c) mod 2^32` với hệ số nhân `a = 1664525` và số gia `c = 1013904223`.
 *   - Dùng phép dịch phải không dấu `>>> 0` để ép kết quả tràn số học JavaScript về miền số nguyên không dấu `uint32` (`[0, 2^32 - 1]`) với độ phức tạp `O(1)` mỗi mẫu.
 */
export function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state;
  };
}

export const baseInput = {
  resourceType: 'DOCUMENT',
  action: 'VIEW',
  subject: {
    clearanceRank: 3,
    departmentId: '10',
    employmentStatus: 'ACTIVE',
    projects: ['ORION'],
  },
  resource: {
    classificationRank: 2,
    ownerId: '99',
    departmentId: '10',
    category: 'SECURITY',
    status: 'ACTIVE',
  },
  environment: {
    currentTime: '2026-01-01T02:00:00.000Z',
    ip: '10.20.30.40',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 20,
  },
};

export function rule(id, conditions, overrides = {}) {
  return {
    id: String(id),
    code: `RULE_${id}`,
    effect: 'PERMIT',
    priority: 100,
    targetResource: 'DOCUMENT',
    targetAction: 'VIEW',
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: '2020-01-01T00:00:00.000Z',
    validTo: null,
    groups: [
      {
        id: 1,
        conditions: conditions.map((condition, index) => ({ id: `${id}-${index}`, ...condition })),
      },
    ],
    obligations: [],
    ...overrides,
  };
}

export function policy(rules, version = '42') {
  return {
    version,
    requiredAttributes: ['resource.classificationRank', 'subject.clearanceRank'],
    rules,
  };
}

export function makeStoredRule(overrides = {}) {
  return {
    id: 1n,
    code: 'STORED_RULE',
    effect: 'PERMIT',
    priority: 1,
    targetResource: 'DOCUMENT',
    targetAction: 'VIEW',
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: new Date('2025-01-01T00:00:00.000Z'),
    validTo: null,
    obligations: [],
    conditions: [
      {
        id: 1n,
        definitionCode: null,
        contextKey: 'environment.mfa',
        operator: 'EQ',
        expectedValue: true,
        group: 1,
        sequence: 1,
      },
    ],
    ...overrides,
  };
}

/**
 * Thuật toán: Bộ Sinh Ngữ cảnh Truy cập ABAC Ngẫu nhiên Phân bố Rời rạc (`randomInput`)
 * Mục đích: Phủ rộng không gian tổ hợp thuộc tính chủ thể (`subject`), tài nguyên (`resource`) và môi trường (`environment`) qua hàng trăm vòng lặp fuzzing.
 * Cơ chế hoạt động:
 *   - Lấy mẫu từ hàm sinh tất định `rand()` qua phép chia lấy dư (`%`) để sinh ngẫu nhiên hành động, cấp độ mật `1..5` (hoặc `null` để kiểm thử thiếu thuộc tính fail-closed), trạng thái nhân sự, địa chỉ IPv4 4-octet và điểm rủi ro `[0, 100]`.
 */
export function randomInput(rand) {
  return {
    resourceType: 'DOCUMENT',
    action: ['DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE'][rand() % 5],
    subject: {
      clearanceRank: rand() % 2 === 0 ? null : (rand() % 5) + 1,
      departmentId: String(rand() % 50),
      employmentStatus: ['ACTIVE', 'LOCKED', 'DISABLED', 'PENDING'][rand() % 4],
      projects: rand() % 3 === 0 ? [] : [`PRJ_${rand() % 10}`],
    },
    resource: {
      classificationRank: rand() % 2 === 0 ? null : (rand() % 5) + 1,
      ownerId: String(rand() % 100),
      departmentId: String(rand() % 50),
      category: ['SECURITY', 'FINANCE', 'HR', 'GENERAL'][rand() % 4],
      status: ['ACTIVE', 'DRAFT', 'ARCHIVED', 'DELETED'][rand() % 4],
    },
    environment: {
      currentTime: new Date(2026, 0, 1 + (rand() % 365), rand() % 24, rand() % 60).toISOString(),
      ip: `${rand() % 256}.${rand() % 256}.${rand() % 256}.${rand() % 256}`,
      trustedNetwork: rand() % 2 === 0,
      deviceTrust: rand() % 2 === 0,
      mfa: rand() % 2 === 0,
      riskScore: rand() % 101,
    },
  };
}
