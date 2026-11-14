/**
 * @module WebAuthnChallengeHelper
 * Thuật toán: Ký không trạng thái thử thách WebAuthn bằng HMAC-SHA256 (TTL 5 phút)
 * và chống phát lại nguyên tử xuyên bản sao qua `DistributedStateService.claimOnce` (`SET NX PX`, fail-closed).
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import type { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';

interface SignedChallengePayload {
  challenge: string;
  userId?: string | undefined;
  timestamp: number;
}

export class WebAuthnChallengeStore {
  private readonly challengeSigningKey: Buffer;
  private readonly stateStore: DistributedStateService;

  constructor(masterKey: string, stateStore?: DistributedStateService, config?: AppConfigService) {
    this.challengeSigningKey = createHash('sha256')
      .update(`webauthn-challenge-token:${masterKey}`)
      .digest();
    this.stateStore = stateStore ?? new DistributedStateService(config);
  }

  /**
   * Thuật toán: Tạo thẻ thử thách không trạng thái có chữ ký HMAC-SHA256 ràng buộc định danh người dùng.
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
   * Thuật toán: Xác minh chữ ký HMAC thời gian hằng số, cửa sổ hiệu lực 5 phút và tiêu thụ nguyên tử một lần trên `DistributedStateService`.
   */
  async verifyChallengeToken(token: string, expectedUserId?: bigint | string): Promise<string> {
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

    const now = Date.now();
    if (now - payload.timestamp > 300_000 || payload.timestamp > now + 30_000) {
      throw new BadRequestException('Challenge token has expired.');
    }

    // CONFLICT-RESOLVED: Bắt buộc `payload.userId` hiện diện và khớp `expectedUserId` để chống chiếm đoạt thử thách chéo tài khoản (HIGH-10).
    if (
      expectedUserId !== undefined &&
      (payload.userId === undefined || payload.userId !== String(expectedUserId))
    ) {
      throw new BadRequestException('Challenge token is bound to a different user.');
    }

    const challengeDigest = createHash('sha256').update(token).digest('hex');
    const ttlMs = Math.max(1_000, payload.timestamp + 300_000 - now);
    const claimed = await this.stateStore.claimOnce('webauthn-challenge', challengeDigest, ttlMs, {
      failClosedInProd: true,
    });
    if (!claimed) {
      throw new BadRequestException('Challenge token has already been used.');
    }

    return payload.challenge;
  }
}
