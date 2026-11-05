import { generateKeyPairSync } from 'node:crypto';
import { importPKCS8, SignJWT } from 'jose';

const pair = generateKeyPairSync('ed25519');
export const privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
export const publicPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();

export function config(overrides = {}) {
  const values = {
    AUTH_ACTIVE_KID: 'test-key',
    AUTH_ACCESS_TTL_SECONDS: 300,
    AUTH_REFRESH_TTL_SECONDS: 604800,
    AUTH_RESET_TTL_SECONDS: 900,
    AUTH_ISSUER: 'test-issuer',
    AUTH_AUDIENCE: 'test-audience',
    AUTH_SIGNING_PRIVATE_KEY_PEM: privatePem,
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([{ kid: 'test-key', publicKeyPem: publicPem }]),
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-that-is-at-least-thirty-two-characters',
    ...overrides,
  };
  return {
    get: (key) => values[key],
    corsOrigins: ['https://app.internal.test'],
    isProduction: true,
  };
}

/**
 * Algorithm: Ed25519 Asymmetric JWT Token Signer (RFC 8037 EdDSA)
 * Description: Signs customizable JWT claims (`issuer`, `audience`, `exp`, `sid`, `mfa`) using an
 *              in-memory PKCS#8 Ed25519 private key to test strict token verification rejections.
 * Time Complexity: O(1) fixed-size Ed25519 elliptic curve signature generation.
 * Space Complexity: O(1) key and token buffer allocation.
 */
/**
 * Thuật toán: Ký Số Mã thông báo JWT Bất đối xứng Đường cong Edwards (`externallySignedToken` — Ed25519 / EdDSA RFC 8037)
 * Mục đích: Sinh chuỗi JWT hợp lệ mật mã học nhưng tùy biến linh hoạt các trường `issuer`, `audience`, `exp` và `claims` để kiểm thử cơ chế từ chối token giả mạo/hết hạn/chưa xác thực MFA.
 * Cơ chế hoạt động:
 *   - Nạp khóa riêng PKCS#8 Ed25519 tạm thời tạo trong bộ nhớ, đóng gói Protected Header `{ alg: 'EdDSA', kid: 'test-key' }` cùng các claim định danh phiên và ký số bằng `SignJWT`.
 */
export async function externallySignedToken(claims = {}, options = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: '11111111-1111-4111-8111-111111111111', mfa: true, ...claims })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key' })
    .setSubject('42')
    .setIssuer(options.issuer ?? 'test-issuer')
    .setAudience(options.audience ?? 'test-audience')
    .setIssuedAt(now - 60)
    .setExpirationTime(options.exp ?? now + 60)
    .setJti('22222222-2222-4222-8222-222222222222')
    .sign(await importPKCS8(privatePem, 'EdDSA'));
}
