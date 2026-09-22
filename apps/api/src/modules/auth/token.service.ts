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

  newOpaqueToken(): string {
    return randomBytes(32).toString('base64url');
  }

  hashOpaqueToken(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }
}
