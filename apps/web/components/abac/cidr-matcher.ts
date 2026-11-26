/**
 * Thuật toán: Đối Chiếu Mặt Nạ Mạng Con IPv4/IPv6 Dual-Stack 32/128-Bit BigInt Đồng Bộ 1-1 Với Backend (`cidr-matcher`, RFC 4291, BUG-039)
 * Cơ chế hoạt động:
 *   1. Phân tích địa chỉ IP nguồn và địa chỉ mạng (kèm cắt bỏ zone index `%eth0`) sang `{ value: bigint, bits: 32 | 128 }`.
 *   2. Chuẩn hóa chéo địa chỉ IPv4-mapped IPv6 (`::ffff:a.b.c.d`, tiền tố 96-bit `0xffff`) và từ chối khớp chéo giữa IPv4 thuần với IPv6 thuần (`address.bits !== network.bits`).
 *   3. Hỗ trợ cả CIDR có `/prefix` lẫn địa chỉ IP đơn lẻ không hậu tố `/`, dịch phải `bits - prefix` bit để so sánh tiền tố mạng.
 */
export function cidrMatch(ip: string, cidr: string): boolean {
  const [networkText, prefixText, extra] = cidr.trim().split('/');
  if (!networkText || extra !== undefined) return false;
  if (prefixText !== undefined && !/^\d{1,3}$/u.test(prefixText)) return false;
  let address = parseAddress(ip);
  const network = parseAddress(networkText);
  if (!address || !network) return false;
  if (address.bits === 128 && network.bits === 32 && address.value >> 32n === 0xffffn) {
    address = { value: address.value & 0xffffffffn, bits: 32 };
  } else if (network.bits === 128 && address.bits === 32 && network.value >> 32n === 0xffffn) {
    address = { value: (0xffffn << 32n) | address.value, bits: 128 };
  }
  if (address.bits !== network.bits) return false;
  const prefix = prefixText === undefined ? address.bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > address.bits) return false;
  const shift = BigInt(address.bits - prefix);
  return address.value >> shift === network.value >> shift;
}

export function isValidCidr(cidr: string): boolean {
  const trimmed = cidr.trim();
  if (trimmed.length === 0) return false;
  const [networkText, prefixText, extra] = trimmed.split('/');
  if (!networkText || extra !== undefined) return false;
  const network = parseAddress(networkText);
  if (!network) return false;
  if (prefixText === undefined) return true;
  if (!/^\d{1,3}$/u.test(prefixText)) return false;
  const prefix = Number(prefixText);
  return Number.isInteger(prefix) && prefix >= 0 && prefix <= network.bits;
}

export function parseAddress(value: string): { value: bigint; bits: 32 | 128 } | null {
  const normalized = value.trim().toLowerCase().split('%')[0]!;
  if (normalized.includes(':')) return parseIpv6(normalized);
  const parts = normalized.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part) || Number(part) > 255)) {
    return null;
  }
  return {
    value: parts.reduce((result, part) => (result << 8n) | BigInt(Number(part)), 0n),
    bits: 32,
  };
}

export function parseIpv6(value: string): { value: bigint; bits: 128 } | null {
  if ((value.match(/::/gu) ?? []).length > 1) return null;
  let source = value;
  const ipv4Tail = source.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/u)?.[1];
  if (ipv4Tail) {
    const parsed = parseAddress(ipv4Tail);
    if (!parsed || parsed.bits !== 32) return null;
    const high = ((parsed.value >> 16n) & 0xffffn).toString(16);
    const low = (parsed.value & 0xffffn).toString(16);
    source = `${source.slice(0, -ipv4Tail.length)}${high}:${low}`;
  }
  const halves = source.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const omitted = 8 - left.length - right.length;
  if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return null;
  const groups = [...left, ...Array.from({ length: omitted }, () => '0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) return null;
  return {
    value: groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n),
    bits: 128,
  };
}

export function canonicalizeIpAddress(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes('/')) return null;
  let parsed = parseAddress(trimmed);
  if (!parsed) return null;
  if (parsed.bits === 128 && parsed.value >> 32n === 0xffffn) {
    parsed = { value: parsed.value & 0xffffffffn, bits: 32 };
  }
  return `${parsed.bits}:${parsed.value.toString(16)}`;
}

export function simulatorCidrMatch(ipRaw: string, cidrRaw: string): boolean {
  return cidrMatch(ipRaw, cidrRaw);
}
