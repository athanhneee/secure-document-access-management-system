/**
 * @module AbacCidr
 * Algorithm: IPv4/IPv6 Dual-Stack 128-bit BigInt Bitwise CIDR Prefix Matching (RFC 4291).
 * Chuẩn hóa địa chỉ mạng IPv4/IPv6 sang số nguyên BigInt 32/128-bit và đối chiếu mặt nạ CIDR.
 */

/**
 * Algorithm / Thuật toán: Đối chiếu mặt nạ mạng con CIDR trên số nguyên lớn 32/128-bit (BigInt Bitwise Prefix Matching).
 * Cơ chế hoạt động:
 *   1. Phân tích địa chỉ IP nguồn và địa chỉ mạng sang biểu diễn nhị phân `{ value: bigint, bits: 32 | 128 }`.
 *   2. Chuẩn hóa chéo địa chỉ IPv4-mapped IPv6 (`::ffff:a.b.c.d`, tiền tố 96-bit `0xffff`) để đối chiếu
 *      tương thích hai chiều giữa client kết nối qua dual-stack IPv6 và dải luật CIDR IPv4.
 *   3. Dịch phải (`>>`) cả địa chỉ lẫn mạng đi `bits - prefix` bit để so sánh phần tiền tố mạng.
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

/**
 * Algorithm / Thuật toán: Xác thực cú pháp nghiêm ngặt chuỗi mạng con IPv4/IPv6 CIDR khi biên dịch chính sách ABAC (HIGH-11).
 */
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

/**
 * Algorithm / Thuật toán: Phân tích chuỗi IPv4 hoặc IPv6 (kèm cắt bỏ zone index `%eth0`) sang số nguyên BigInt.
 * Cơ chế hoạt động: Với IPv4, kiểm tra 4 octet thập phân `[0..255]` và ghép dịch trái 8-bit (`<< 8n`) thành số 32-bit.
 */
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

/**
 * Algorithm / Thuật toán: Chuẩn hóa và giải nén địa chỉ IPv6 chuẩn RFC 4291 sang số nguyên không dấu 128-bit BigInt.
 * Cơ chế hoạt động:
 *   1. Đảm bảo ký hiệu rút gọn chuỗi 0 (`::`) xuất hiện tối đa 1 lần.
 *   2. Nếu có phần đuôi lai IPv4 (ví dụ `::ffff:192.168.1.1`), chuyển 32-bit cuối thành 2 nhóm hextet 16-bit.
 *   3. Tính số lượng hextet bị lược bỏ `omitted = 8 - left.length - right.length` và điền bù các nhóm `'0'`.
 *   4. Xác thực đủ 8 nhóm hex 16-bit và ghép tuần tự bằng phép dịch bit `(result << 16n) | hextet`.
 */
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
