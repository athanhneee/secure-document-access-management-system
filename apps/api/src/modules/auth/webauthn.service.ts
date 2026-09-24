import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
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

interface SignedChallengePayload {
  challenge: string;
  userId?: string | undefined;
  timestamp: number;
}

@Injectable()
export class WebAuthnService {
  private readonly rpName: string;
  private readonly rpId: string;
  private readonly origins: string[];
  private readonly challengeSigningKey: Buffer;

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

    const master = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.challengeSigningKey = createHash('sha256')
      .update(`webauthn-challenge-token:${master}`)
      .digest();
  }

  getRpId(): string {
    return this.rpId;
  }

  getOrigins(): string[] {
    return this.origins;
  }

  /**
   * Generates a signed, stateless challenge token with 5-minute TTL.
   * Tamper-proof and binds to the target user (if provided).
   */
  createChallengeToken(challenge: string, userId?: bigint | string): string {
    const payload: SignedChallengePayload = {
      challenge,
      userId: userId !== undefined ? String(userId) : undefined,
      timestamp: Date.now(),
    };
    const serialized = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = createHmac('sha256', this.challengeSigningKey)
      .update(serialized)
      .digest('base64url');
    return `${serialized}.${signature}`;
  }

  /**
   * Verifies the stateless challenge token and extracts the expected challenge.
   */
  verifyChallengeToken(token: string, expectedUserId?: bigint | string): string {
    const parts = token.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new BadRequestException('Invalid challenge token format.');
    }
    const serialized = parts[0];
    const signature = parts[1];

    const expectedSignature = createHmac('sha256', this.challengeSigningKey)
      .update(serialized)
      .digest('base64url');

    const signatureBuffer = Buffer.from(signature, 'utf8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

    if (
      signatureBuffer.length !== expectedBuffer.length ||
      !timingSafeEqual(signatureBuffer, expectedBuffer)
    ) {
      throw new BadRequestException('Challenge token signature verification failed.');
    }

    let payload: SignedChallengePayload;
    try {
      payload = JSON.parse(
        Buffer.from(serialized, 'base64url').toString('utf8'),
      ) as SignedChallengePayload;
    } catch {
      throw new BadRequestException('Malformed challenge token payload.');
    }

    // Enforce 5-minute maximum lifetime
    if (Date.now() - payload.timestamp > 300_000) {
      throw new BadRequestException('Challenge token has expired.');
    }

    if (
      expectedUserId !== undefined &&
      payload.userId !== undefined &&
      payload.userId !== String(expectedUserId)
    ) {
      throw new BadRequestException('Challenge token is bound to a different user.');
    }

    return payload.challenge;
  }

  /**
   * Generates registration options conforming to W3C WebAuthn Level 3.
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
   * Verifies registration response from client and returns encrypted credential for database persistence.
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
   * Generates authentication options for an existing user's registered keys.
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
   * Verifies authentication response from client with clone detection.
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

    const webauthnCred: WebAuthnCredential = {
      id: stored.credentialId,
      publicKey: new Uint8Array(Buffer.from(stored.publicKeyBase64Url, 'base64url')),
      counter: stored.counter,
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

    // Clone Detection: Authenticator counter must increase if counter > 0
    if (stored.counter > 0 && newCounter <= stored.counter) {
      return {
        verified: false,
        cloneDetected: true,
        newCounter,
        updatedEncryptedSecret: this.mfa.encryptPayload(stored),
      };
    }

    // Update stored counter
    const updatedCredential: StoredWebAuthnCredential = {
      ...stored,
      counter: newCounter,
    };
    const updatedEncryptedSecret = this.mfa.encryptPayload(updatedCredential);

    return {
      verified: true,
      cloneDetected: false,
      newCounter,
      updatedEncryptedSecret,
    };
  }

  /**
   * Helper to parse stored credential from database secret string.
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
