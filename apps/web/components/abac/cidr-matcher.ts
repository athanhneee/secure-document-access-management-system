/**
 * Thuật toán: Đối Sánh Mặt Nạ Mạng Con IPv4/IPv6 CIDR 128-Bit Hằng Độ Phức Tạp (`simulatorCidrMatch`)
 * Mục đích: Xác minh địa chỉ IP nguồn (IPv4 hoặc IPv6 nén `::`) có thuộc dải mạng con CIDR được phép trong chính sách ABAC hay không.
 * Cơ chế hoạt động:
 *   - Chuyển đổi IPv4 sang không gian IPv4-mapped IPv6 `::ffff:0:0/96` và khai triển IPv6 nén thành số nguyên `BigInt` 128-bit.
 *   - Dựng mặt nạ bit bậc cao `mask` theo độ dài tiền tố hiệu dụng và đối chiếu `(candidate.bits & mask) === (network.bits & mask)`.
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
