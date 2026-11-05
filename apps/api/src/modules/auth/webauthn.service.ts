/**
 * @module WebAuthnService
 * Algorithm: W3C WebAuthn Level 3 Registration, Attestation & Sign-Counter Clone Detection.
 */
import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { MfaService } from './mfa.service.js';
import { WebAuthnChallengeStore } from './webauthn-challenge.helper.js';

export interface StoredWebAuthnCredential {
  type: 'WEBAUTHN';
  credentialId: string;
  publicKeyBase64Url: string;
  counter: number;
  transports?: string[] | undefined;
  aaguid?: string | undefined;
  deviceName?: string | undefined;
  createdAt: string;
}

@Injectable()
export class WebAuthnService {
  private readonly rpName: string;
  private readonly rpId: string;
  private readonly origins: string[];
  private readonly challenges: WebAuthnChallengeStore;

  constructor(
    private readonly mfa: MfaService,
    config: AppConfigService,
  ) {
    this.rpName = config.get('WEBAUTHN_RP_NAME') || 'Secure Document Access';
    this.rpId = config.get('WEBAUTHN_RP_ID') || 'localhost';
    const rawOrigins =
      config.get('WEBAUTHN_ORIGINS') || 'http://localhost:3000,http://127.0.0.1:3000';
    this.origins = rawOrigins
      .split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0);
    this.challenges = new WebAuthnChallengeStore(config.get('APP_ENCRYPTION_MASTER_KEY'));
  }

  getRpId(): string {
    return this.rpId;
  }

  getOrigins(): string[] {
    return this.origins;
  }

  createChallengeToken(challenge: string, userId?: bigint | string): string {
    return this.challenges.createChallengeToken(challenge, userId);
  }

  verifyChallengeToken(token: string, expectedUserId?: bigint | string): string {
    return this.challenges.verifyChallengeToken(token, expectedUserId);
  }

  /**
   * Algorithm / Thuật toán: Sinh tham số đăng ký khóa phần cứng chuẩn W3C WebAuthn Level 3 kèm loại trừ khóa đã đăng ký.
   */
  async generateRegistrationOptions(
    userId: bigint,
    username: string,
    existingCredentials: StoredWebAuthnCredential[] = [],
  ) {
    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userID: Buffer.from(String(userId)),
      userName: username,
      userDisplayName: username,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map((c) => ({
        id: c.credentialId,
        ...(c.transports ? { transports: [...c.transports] } : {}),
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    const challengeToken = this.createChallengeToken(options.challenge, userId);
    return { options, challengeToken };
  }

  /**
   * Algorithm / Thuật toán: Xác minh chứng thực đăng ký FIDO2/WebAuthn và mã hóa khóa công khai lưu trữ an toàn.
   */
  async verifyRegistration(
    response: RegistrationResponseJSON,
    challengeToken: string,
    userId: bigint,
    label?: string,
  ): Promise<{
    verified: boolean;
    credential: StoredWebAuthnCredential;
    encryptedSecret: string;
  }> {
    const expectedChallenge = this.verifyChallengeToken(challengeToken, userId);

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origins,
      expectedRPID: this.rpId,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new BadRequestException('FIDO2 / WebAuthn registration verification failed.');
    }

    const { credential, aaguid } = verification.registrationInfo;

    const stored: StoredWebAuthnCredential = {
      type: 'WEBAUTHN',
      credentialId: credential.id,
      publicKeyBase64Url: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      transports: credential.transports ? [...credential.transports] : undefined,
      aaguid: aaguid ?? undefined,
      deviceName: label?.trim() || 'FIDO2 / WebAuthn Key',
      createdAt: new Date().toISOString(),
    };

    const encryptedSecret = this.mfa.encryptPayload(stored);
    return { verified: true, credential: stored, encryptedSecret };
  }

  /**
   * Algorithm / Thuật toán: Sinh thử thách xác thực WebAuthn cho tập khóa phần cứng hiện có của tài khoản.
   */
  async generateAuthenticationOptions(credentials: StoredWebAuthnCredential[], userId?: bigint) {
    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      allowCredentials: credentials.map((c) => ({
        id: c.credentialId,
        ...(c.transports ? { transports: [...c.transports] } : {}),
      })),
      userVerification: 'preferred',
    });

    const challengeToken = this.createChallengeToken(options.challenge, userId);
    return { options, challengeToken };
  }

  /**
   * Algorithm / Thuật toán: Kiểm chứng chữ ký xác thực WebAuthn kèm phát hiện nhân bản khóa qua bộ đếm đơn điệu (`newCounter > stored.counter`).
   */
  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    challengeToken: string,
    stored: StoredWebAuthnCredential,
    userId?: bigint,
  ): Promise<{
    verified: boolean;
    cloneDetected: boolean;
    newCounter: number;
    updatedEncryptedSecret: string;
  }> {
    const expectedChallenge = this.verifyChallengeToken(challengeToken, userId);

    // Pass counter: 0 to @simplewebauthn/server so cryptographic signature verification completes
    // without prematurely throwing on counter rollback, allowing explicit clone detection below.
    const webauthnCred: WebAuthnCredential = {
      id: stored.credentialId,
      publicKey: new Uint8Array(Buffer.from(stored.publicKeyBase64Url, 'base64url')),
      counter: 0,
      ...(stored.transports ? { transports: [...stored.transports] } : {}),
    };

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origins,
      expectedRPID: this.rpId,
      credential: webauthnCred,
      requireUserVerification: false,
    });

    if (!verification.verified) {
      throw new UnauthorizedException('FIDO2 / WebAuthn authentication failed.');
    }

    const { newCounter } = verification.authenticationInfo;

    if (stored.counter > 0 && newCounter <= stored.counter) {
      return {
        verified: false,
        cloneDetected: true,
        newCounter,
        updatedEncryptedSecret: this.mfa.encryptPayload(stored),
      };
    }

    const updatedCredential: StoredWebAuthnCredential = { ...stored, counter: newCounter };
    return {
      verified: true,
      cloneDetected: false,
      newCounter,
      updatedEncryptedSecret: this.mfa.encryptPayload(updatedCredential),
    };
  }

  /**
   * Algorithm / Thuật toán: Giải mã và thu hẹp kiểu an toàn cấu trúc khóa WebAuthn từ chuỗi bí mật lưu trong DB.
   */
  parseStoredCredential(encryptedSecret: string): StoredWebAuthnCredential | null {
    try {
      const decrypted = this.mfa.decryptPayload<Record<string, unknown>>(encryptedSecret);
      if (
        decrypted &&
        decrypted['type'] === 'WEBAUTHN' &&
        typeof decrypted['credentialId'] === 'string'
      ) {
        return decrypted as unknown as StoredWebAuthnCredential;
      }
      return null;
    } catch {
      return null;
    }
  }
}
