import type { VisualPolicyRule, VisualCondition, TargetAction, TimeWindow } from './abac-models';
import {
  buildSimulationPreset,
  type SimulationPresetName,
  type SimulationSubject,
  type SimulationResource,
  type SimulationEnvironment,
  type SimulationResult,
} from './simulator-presets';

export {
  buildSimulationPreset,
  type SimulationPresetName,
  type SimulationSubject,
  type SimulationResource,
  type SimulationEnvironment,
  type SimulationResult,
};

/**
 * Algorithm / Thuật toán: Bộ Đánh Giá Biểu Thức Chính Sách Dạng Chuẩn Tuyển DNF & Luật Kết Hợp XACML DENY_OVERRIDES
 * Mục đích: Xác định quyết định cấp quyền (`PERMIT` / `DENY`), mã lý do (`reasonCode`), vết đánh giá từng nhánh logic và gộp danh sách nghĩa vụ (`obligations`).
 * Cơ chế hoạt động:
 *   - Bước 1: Phẳng hóa không gian thuộc tính 3 chiều `(subject, resource, environment)` thành bảng tra cứu khóa phẳng `O(1)`.
 *   - Bước 2: Kiểm tra phạm vi hành động mục tiêu (`targetAction === 'ALL'` hoặc trùng khớp `action`); nếu lệch thì trả về `DENY` (`ACTION_NOT_TARGETED`) theo nguyên lý Fail-Secure.
 *   - Bước 3: Duyệt cấu trúc DNF độ phức tạp `O(G * C)` — mỗi nhóm điều kiện (`group`) thỏa mãn khi không rỗng và mọi vị từ con đồng thời đúng (AND `every`); toàn quy tắc khớp khi tồn tại ít nhất một nhóm thỏa mãn (OR `some`).
 *   - Bước 4: Áp dụng hiệu lực `effect` của quy tắc hoặc rơi về `DEFAULT_DENY_NO_GROUP_MATCH`.
 */
export function evaluatePolicySimulation(
  activeRule: VisualPolicyRule,
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
  const flatAttributes: Record<string, unknown> = {
    'subject.clearanceRank': subject.clearanceRank,
    'subject.departmentId': subject.departmentId,
    'subject.employmentStatus': subject.employmentStatus,
    'subject.projects': subject.projects,
    'resource.classificationRank': resource.classificationRank,
    'resource.departmentId': resource.departmentId,
    'resource.category': resource.category,
    'resource.status': resource.status,
    'resource.ownerId': resource.ownerId,
    'environment.currentTime': environment.currentTime,
    'environment.ip': environment.ip,
    'environment.trustedNetwork': environment.trustedNetwork,
    'environment.deviceTrust': environment.deviceTrust,
    'environment.mfa': environment.mfa,
    'environment.riskScore': environment.riskScore,
  };

  if (activeRule.targetAction !== 'ALL' && activeRule.targetAction !== action) {
    return {
      decision: 'DENY',
      reasonCode: 'ACTION_NOT_TARGETED',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  const groupEvaluations = activeRule.groups.map((group) => {
    const conditionResults = group.conditions.map((cond) => {
      const actual = flatAttributes[cond.attribute];
      return {
        conditionId: cond.id,
        attribute: cond.attribute,
        operator: cond.operator,
        expected: cond.expected,
        actual,
        matched: evaluateCondition(cond, actual),
      };
    });
    return {
      groupId: group.id,
      satisfied: conditionResults.length > 0 && conditionResults.every((c) => c.matched),
      conditionResults,
    };
  });

  if (!groupEvaluations.some((g) => g.satisfied)) {
    return {
      decision: 'DENY',
      reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations,
    };
  }

  return activeRule.effect === 'PERMIT'
    ? {
        decision: 'PERMIT',
        reasonCode: 'RULE_PERMIT_MATCHED',
        matchedRuleCodes: [activeRule.code],
        obligations: activeRule.obligations,
        groupEvaluations,
      }
    : {
        decision: 'DENY',
        reasonCode: 'EXPLICIT_DENY_RULE_MATCHED',
        matchedRuleCodes: [activeRule.code],
        obligations: activeRule.obligations,
        groupEvaluations,
      };
}

const STRICT_ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

function toComparableScalar(value: unknown): number | string | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  if (STRICT_ISO_DATE_PATTERN.test(value)) {
    const ts = Date.parse(value);
    return Number.isFinite(ts) ? ts : null;
  }
  return value;
}

function compareScalars(leftRaw: unknown, rightRaw: unknown): number {
  const left = toComparableScalar(leftRaw);
  const right = toComparableScalar(rightRaw);
  if (left === null || right === null || typeof left !== typeof right) return Number.NaN;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return String(left).localeCompare(String(right));
}

/**
 * Algorithm / Thuật toán: Chuẩn Hóa Địa Chỉ IPv4/IPv6 Sang Số Nguyên 128-Bit & Đối Sánh Mặt Nạ CIDR (128-Bit BigInt CIDR Matcher)
 * Mục đích: Xác định chính xác địa chỉ IP thực tế thuộc dải mạng con `/0`..`/32` (IPv4) hoặc `/0`..`/128` (IPv6) mà không cắt chuỗi 3 octet thủ công.
 * Cơ chế hoạt động:
 *   - Ánh xạ IPv4 sang không gian IPv4-mapped IPv6 `::ffff:a.b.c.d` (cộng bù 96 bit vào độ dài tiền tố).
 *   - Khai triển ký hiệu nén `::` của IPv6 thành đủ 8 nhóm 16-bit (`hextet`) tạo số nguyên 128-bit `BigInt`.
 *   - Dựng mặt nạ bit bậc cao `mask` và kiểm tra đẳng thức `(candidate & mask) === (network & mask)`.
 */
function parseIpv4Bits(ip: string): bigint | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return (0xffffn << 32n) | value;
}

function parseIp128(rawIp: string): { bits: bigint; isIpv4: boolean } | null {
  const trimmed = rawIp.trim();
  const v4 = parseIpv4Bits(trimmed);
  if (v4 !== null) return { bits: v4, isIpv4: true };
  if (!trimmed.includes(':') || trimmed.includes(':::')) return null;

  let normalized = trimmed;
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    const embeddedV4 = parseIpv4Bits(normalized.slice(lastColon + 1));
    if (embeddedV4 === null) return null;
    const low32 = embeddedV4 & 0xffffffffn;
    const hi = Number((low32 >> 16n) & 0xffffn).toString(16);
    const lo = Number(low32 & 0xffffn).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if ((halves.length === 1 && left.length !== 8) || (halves.length === 2 && missing < 1)) {
    return null;
  }
  const groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    result = (result << 16n) | BigInt(Number.parseInt(group, 16));
  }
  return { bits: result, isIpv4: false };
}

export function simulatorCidrMatch(ipRaw: string, cidrRaw: string): boolean {
  const candidate = parseIp128(ipRaw);
  if (!candidate) return false;
  const slashIdx = cidrRaw.indexOf('/');
  if (slashIdx <= 0) return false;
  const network = parseIp128(cidrRaw.slice(0, slashIdx));
  const prefixText = cidrRaw.slice(slashIdx + 1);
  if (!network || !/^\d{1,3}$/.test(prefixText)) return false;
  const prefixLen = Number(prefixText);
  const maxPrefix = network.isIpv4 ? 32 : 128;
  if (prefixLen < 0 || prefixLen > maxPrefix) return false;
  const effectivePrefix = network.isIpv4 ? 96 + prefixLen : prefixLen;
  if (effectivePrefix === 0) return true;
  const shift = BigInt(128 - effectivePrefix);
  const mask = ((1n << BigInt(effectivePrefix)) - 1n) << shift;
  return (candidate.bits & mask) === (network.bits & mask);
}

/**
 * Algorithm / Thuật toán: Đối Sánh Vị Từ Thuộc Tính Đa Hình (Polymorphic Attribute Predicate Evaluator)
 * Cơ chế hoạt động:
 *   - Toán tử `EXISTS` kiểm tra khác rỗng; các toán tử còn lại trả về `false` ngay khi thực tế rỗng (Fail-Closed).
 *   - Hỗ trợ so sánh thứ bậc an toàn kiểu (`GTE`, `LTE`, `BETWEEN`), tập hợp (`IN`, `NOT_IN`), khung giờ 24h có vắt qua nửa đêm (`TIME_BETWEEN`) và mặt nạ mạng con 128-bit (`CIDR_MATCH`).
 */
export function evaluateCondition(cond: VisualCondition, actual: unknown): boolean {
  if (cond.operator === 'EXISTS') return actual !== undefined && actual !== null && actual !== '';
  if (actual === undefined || actual === null) return false;

  switch (cond.operator) {
    case 'EQ':
      return actual === cond.expected;
    case 'NEQ':
      return actual !== cond.expected;
    case 'GTE':
      return compareScalars(actual, cond.expected) >= 0;
    case 'LTE':
      return compareScalars(actual, cond.expected) <= 0;
    case 'BETWEEN':
      if (Array.isArray(cond.expected) && cond.expected.length === 2) {
        return (
          compareScalars(actual, cond.expected[0]) >= 0 &&
          compareScalars(actual, cond.expected[1]) <= 0
        );
      }
      return false;
    case 'IN':
      if (!Array.isArray(cond.expected)) return false;
      return Array.isArray(actual)
        ? actual.some((a) => (cond.expected as unknown[]).includes(a))
        : (cond.expected as unknown[]).includes(actual);
    case 'NOT_IN':
      if (!Array.isArray(cond.expected)) return false;
      return Array.isArray(actual)
        ? !actual.some((a) => (cond.expected as unknown[]).includes(a))
        : !(cond.expected as unknown[]).includes(actual);
    case 'TIME_BETWEEN':
      if (typeof cond.expected === 'object' && cond.expected !== null) {
        const tw = cond.expected as TimeWindow;
        const current = String(actual);
        return tw.start <= tw.end
          ? current >= tw.start && current <= tw.end
          : current >= tw.start || current <= tw.end;
      }
      return false;
    case 'CIDR_MATCH':
      if (typeof cond.expected === 'string' && typeof actual === 'string') {
        return simulatorCidrMatch(actual, cond.expected);
      }
      return false;
    default:
      return false;
  }
}
