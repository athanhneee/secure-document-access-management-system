/**
 * @module TokenService
 * Dịch vụ ký số bất đối xứng JWT trên đường cong xoắn Ed25519 (EdDSA - RFC 8037),
 * hỗ trợ xoay vòng khóa công khai JWKS (RFC 7517) theo định danh `kid` và băm SHA-256 cho Opaque Refresh Token.
 */
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignJWT, exportJWK, importPKCS8, importSPKI, jwtVerify, type JWTPayload } from 'jose';
import { AppConfigService } from '../../config/config.service.js';

export interface AccessClaims extends JWTPayload {
  sub: string;
  sid: string;
  mfa: boolean;
}

interface PublicKeyConfig {
  kid: string;
  publicKeyPem: string;
}

@Injectable()
export class TokenService {
  private readonly activeKid: string;
  private readonly privateKeyPromise: ReturnType<typeof importPKCS8>;
  private readonly publicKeyPromises = new Map<string, ReturnType<typeof importSPKI>>();
  private readonly accessTtlSeconds: number;
  private readonly issuer: string;
  private readonly audience: string;

  /**
   * Thuật toán: Nạp vòng khóa bất đối xứng Ed25519 (PKCS#8 Private Key & Multi-KID SPKI Keyring).
   * Cơ chế hoạt động: Xác thực khóa ký hiện hành `activeKid` phải nằm trong tập khóa công khai xác minh,
   * cho phép duy trì song song nhiều khóa công khai cũ trong quá trình xoay vòng khóa không gián đoạn phiên.
   */
  constructor(config: AppConfigService) {
    this.activeKid = config.get('AUTH_ACTIVE_KID');
    this.accessTtlSeconds = config.get('AUTH_ACCESS_TTL_SECONDS');
    this.issuer = config.get('AUTH_ISSUER');
    this.audience = config.get('AUTH_AUDIENCE');

    let privatePem = config.get('AUTH_SIGNING_PRIVATE_KEY_PEM');
    let publicKeys: PublicKeyConfig[];
    const configuredPublicKeys = config.get('AUTH_SIGNING_PUBLIC_KEYS_JSON');
    if (privatePem && configuredPublicKeys) {
      publicKeys = JSON.parse(configuredPublicKeys) as PublicKeyConfig[];
    } else {
      const pair = generateKeyPairSync('ed25519');
      privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      publicKeys = [
        {
          kid: this.activeKid,
          publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        },
      ];
    }
    if (!publicKeys.some((item) => item.kid === this.activeKid)) {
      throw new Error('AUTH_ACTIVE_KID must be present in AUTH_SIGNING_PUBLIC_KEYS_JSON.');
    }
    this.privateKeyPromise = importPKCS8(privatePem, 'EdDSA');
    for (const item of publicKeys) {
      if (!item.kid || !item.publicKeyPem || this.publicKeyPromises.has(item.kid)) {
        throw new Error('Signing public keys must have unique non-empty kid values.');
      }
      this.publicKeyPromises.set(item.kid, importSPKI(item.publicKeyPem, 'EdDSA'));
    }
  }

  /**
   * Thuật toán: Phát hành và ký số JWT bằng thuật toán chữ ký đường cong Edwards EdDSA (Ed25519).
   * Cơ chế hoạt động: Đóng gói protected header `{ alg: 'EdDSA', kid, typ: 'JWT' }` chống tấn công hạ cấp `alg: none`,
   * gắn định danh duy nhất `jti` (UUIDv4), trạng thái `mfa` và thời hạn ngắn `accessTtlSeconds`.
   */
  async issueAccessToken(userId: bigint, sessionId: string, mfa: boolean): Promise<string> {
    return new SignJWT({ sid: sessionId, mfa })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.activeKid, typ: 'JWT' })
      .setSubject(userId.toString())
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${this.accessTtlSeconds}s`)
      .sign(await this.privateKeyPromise);
  }

  /**
   * Thuật toán: Xác minh chữ ký JWT EdDSA tra cứu khóa động theo `kid` chống tấn công Algorithm Confusion.
   * Cơ chế hoạt động:
   *   1. Khóa cứng danh sách thuật toán chỉ chấp nhận `['EdDSA']` và đối chiếu `header.kid` trong bảng băm khóa công khai.
   *   2. Kiểm chứng chữ ký mật mã, `issuer`, `audience`, các claim bắt buộc (`sub`, `sid`, `iat`, `exp`, `jti`)
   *      với sai số đồng hồ tối đa 5 giây (`clockTolerance: 5`).
   */
  async verifyAccessToken(token: string): Promise<AccessClaims> {
    try {
      const verified = await jwtVerify(
        token,
        async (header) => {
          if (header.alg !== 'EdDSA' || !header.kid) throw new Error('Unsupported signing key.');
          const key = this.publicKeyPromises.get(header.kid);
          if (!key) throw new Error('Unknown signing key.');
          return key;
        },
        {
          algorithms: ['EdDSA'],
          issuer: this.issuer,
          audience: this.audience,
          clockTolerance: 5,
          requiredClaims: ['sub', 'sid', 'iat', 'exp', 'jti'],
        },
      );
      const payload = verified.payload;
      if (
        typeof payload.sub !== 'string' ||
        typeof payload['sid'] !== 'string' ||
        typeof payload['mfa'] !== 'boolean'
      ) {
        throw new Error('Malformed access token.');
      }
      return payload as AccessClaims;
    } catch {
      throw new UnauthorizedException('Authentication required.');
    }
  }

  /**
   * Thuật toán: Xuất tập khóa công khai định dạng chuẩn JSON Web Key Set (JWKS - RFC 7517 / RFC 8037 OKP).
   */
  async jwks(): Promise<{ keys: Array<Record<string, unknown>> }> {
    const keys = await Promise.all(
      [...this.publicKeyPromises.entries()].map(async ([kid, key]) => ({
        ...(await exportJWK(await key)),
        kid,
        alg: 'EdDSA',
        use: 'sig',
      })),
    );
    return { keys };
  }

  /**
   * Thuật toán: Sinh chuỗi token mờ 256-bit ngẫu nhiên an toàn mật mã (CSPRNG Base64URL Opaque Token).
   */
  newOpaqueToken(): string {
    return randomBytes(32).toString('base64url');
  }

  /**
   * Thuật toán: Băm một chiều SHA-256 cho Opaque Refresh / Reset Token trước khi lưu trữ hoặc tra cứu DB.
   */
  hashOpaqueToken(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }
}
