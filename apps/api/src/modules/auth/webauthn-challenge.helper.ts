/**
 * @module WebAuthnChallengeHelper
 * Algorithm: Stateless HMAC-SHA256 Signed Challenge Token & Two-Tier TTL/FIFO Anti-Replay Cache.
 * Ký không trạng thái thử thách WebAuthn bằng HMAC-SHA256 (TTL 5 phút) và chống phát lại bằng bộ nhớ đệm hai ngưỡng.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';

interface SignedChallengePayload {
  challenge: string;
  userId?: string | undefined;
  timestamp: number;
}

export class WebAuthnChallengeStore {
  private readonly challengeSigningKey: Buffer;
  // shortcut: 8,192 consumed challenge digests (~1 MB) per replica, move to Redis SET NX PX 300000 for multi-replica anti-replay
  private readonly consumedChallenges = new Map<string, number>();

  constructor(masterKey: string) {
    this.challengeSigningKey = createHash('sha256')
      .update(`webauthn-challenge-token:${masterKey}`)
      .digest();
  }

  /**
   * Algorithm / Thuật toán: Tạo thẻ thử thách không trạng thái có chữ ký HMAC-SHA256 ràng buộc định danh người dùng.
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
   * Algorithm / Thuật toán: Xác minh chữ ký HMAC thời gian hằng số, cửa sổ hiệu lực 5 phút và tiêu thụ một lần chống Replay.
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

    const now = Date.now();
    if (now - payload.timestamp > 300_000 || payload.timestamp > now + 30_000) {
      throw new BadRequestException('Challenge token has expired.');
    }

    if (
      expectedUserId !== undefined &&
      payload.userId !== undefined &&
      payload.userId !== String(expectedUserId)
    ) {
      throw new BadRequestException('Challenge token is bound to a different user.');
    }

    this.pruneConsumedChallenges(now);
    const replayKey = createHash('sha256').update(token).digest('hex');
    const consumedExpiry = this.consumedChallenges.get(replayKey);
    if (consumedExpiry && consumedExpiry > now) {
      throw new BadRequestException('Challenge token has already been used.');
    }
    this.consumedChallenges.set(replayKey, payload.timestamp + 300_000);

    return payload.challenge;
  }

  /**
   * Algorithm / Thuật toán: Cắt tỉa bộ nhớ đệm chống phát lại thử thách hai ngưỡng (Two-Tier TTL & FIFO Replay Cache Eviction).
   * Khi bảng vượt 4.096 mục, quét xóa các thử thách đã hết hạn TTL; nếu vẫn đạt trần cứng 8.192 mục,
   * trục xuất theo thứ tự chèn cũ nhất (FIFO trên Map) để bảo vệ giới hạn bộ nhớ tiến trình.
   */
  private pruneConsumedChallenges(now: number): void {
    if (this.consumedChallenges.size < 4_096) return;
    for (const [key, expiresAt] of this.consumedChallenges) {
      if (expiresAt <= now) {
        this.consumedChallenges.delete(key);
      }
    }
    while (this.consumedChallenges.size >= 8_192) {
      const oldest = this.consumedChallenges.keys().next().value;
      if (!oldest) break;
      this.consumedChallenges.delete(oldest);
    }
  }
}
