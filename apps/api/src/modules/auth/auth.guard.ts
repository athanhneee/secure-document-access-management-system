/**
 * @module AuthGuard
 * Thuật toán: Cổng xác thực phiên hai tầng L1 In-Memory + L2 Redis MGET (TTL 60 giây) đồng bộ vô hiệu hóa tức thì
 * qua Redis Pub/Sub (`auth-global`, `auth-user:<id>`, `key:auth-session:<sid>`), kết hợp cập nhật `last_seen_at`
 * phi chặn (non-blocking) trên luồng nóng và cách ly nghiêm ngặt phiên tiền-MFA.
 */
import {
  Injectable,
  Optional,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
  type OnModuleDestroy,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';
import { DefaultDenyGuard } from '../../default-deny.guard.js';
import {
  DistributedStateService,
  type CacheInvalidationEvent,
} from '../concurrency/distributed-state.service.js';
import { ALLOW_PRE_MFA_METADATA } from './allow-pre-mfa.js';
import { AuthRepository } from './auth.repository.js';
import { MFA_REQUIRED_ROLES, type AuthPrincipal } from './auth.types.js';
import { TokenService } from './token.service.js';

const AUTH_SESSION_CACHE_TTL_MS = 60_000;
const DEFAULT_SESSION_TOUCH_INTERVAL_MS = 60_000;
const MAX_L1_SESSIONS = 5_000;
const MAX_LOCAL_TOUCH_KEYS = 10_000;

interface CachedAuthPrincipal {
  userId: string;
  sessionId: string;
  username: string;
  roles: string[];
  mfa: boolean;
  mfaPending?: boolean | undefined;
  restrictedNonBusiness?: boolean | undefined;
  userEpoch: number;
  globalEpoch: number;
}

interface L1SessionEntry {
  principal: AuthPrincipal;
  expiresAt: number;
}

@Injectable()
export class AuthGuard implements CanActivate, OnModuleDestroy {
  private readonly defaultDenyGuard: DefaultDenyGuard;
  private readonly stateStore: DistributedStateService;
  private readonly touchIntervalMs: number;
  private readonly l1Sessions = new Map<string, L1SessionEntry>();
  private readonly localTouchThrottle = new Map<string, number>();
  private readonly unsubscribeInvalidation: (() => void) | null = null;
  private generation = 0;

  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly repository: AuthRepository,
    @Optional() defaultDenyGuard?: DefaultDenyGuard,
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.defaultDenyGuard = defaultDenyGuard ?? new DefaultDenyGuard(reflector);
    this.stateStore = stateStore ?? new DistributedStateService(config);
    const configuredTouchSec = config?.get('AUTH_SESSION_TOUCH_INTERVAL_SECONDS');
    this.touchIntervalMs =
      typeof configuredTouchSec === 'number' && configuredTouchSec > 0
        ? configuredTouchSec * 1_000
        : DEFAULT_SESSION_TOUCH_INTERVAL_MS;
    if (typeof this.stateStore.onInvalidate === 'function') {
      this.unsubscribeInvalidation = this.stateStore.onInvalidate((event) => {
        this.handleCacheInvalidation(event);
      });
    }
  }

  onModuleDestroy(): void {
    this.unsubscribeInvalidation?.();
    this.l1Sessions.clear();
    this.localTouchThrottle.clear();
  }

  /**
   * Thuật toán: Thẩm định JWT EdDSA, tra cứu đệm L1 (~0ms) -> L2 Redis `MGET` 1-RTT (TTL 60s) đồng bộ vô hiệu hóa tức thì
   * qua Pub/Sub, đóng an toàn khi phiên bị thu hồi/khóa và cập nhật dấu vết hoạt động không chặn phản hồi HTTP.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.defaultDenyGuard.canActivate(context)) {
      return true;
    }
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const token = request.cookies?.['sda_access'];
    if (!token) throw new UnauthorizedException('Authentication required.');
    const claims = await this.tokens.verifyAccessToken(token);
    const userId = BigInt(claims.sub);
    const sessionId = claims['sid'];
    const principal = await this.resolveSessionPrincipal(userId, sessionId);
    if (!principal || principal.mfa !== claims.mfa) {
      this.l1Sessions.delete(sessionId);
      await this.stateStore.deleteKey('auth-session', sessionId);
      throw new UnauthorizedException('Session is no longer valid.');
    }
    const preMfaAllowed =
      this.reflector.get<unknown>(ALLOW_PRE_MFA_METADATA, context.getHandler()) === true;
    const mfaPending =
      !principal.mfa &&
      (principal.mfaPending === true ||
        (principal.mfaPending === undefined &&
          (principal.roles ?? []).some((role) => MFA_REQUIRED_ROLES.has(role))));
    if (mfaPending && !preMfaAllowed) {
      throw new UnauthorizedException('MFA verification is required.');
    }
    request.auth = principal;
    await this.touchSessionActivityThrottled(principal.userId, principal.sessionId, request.ip);
    return true;
  }

  /**
   * Thuật toán: Điều tiết cập nhật `last_seen_at` & `ip_address` bằng bộ lọc cục bộ 0ms kết hợp nền phi chặn (Non-Blocking Background Touch).
   * - Nếu cặp `${sessionId}:${ip}` đã được chạm trong cửa sổ `touchIntervalMs` trên tiến trình hiện tại -> bỏ qua ngay trong `O(1)` (`0ms`, 0 RTT mạng).
   * - Khi đổi IP hoặc hết cửa sổ: với Redis thật chạy bất đồng bộ ở nền (không chặn phản hồi HTTP); trong kiểm thử cục bộ chờ đồng bộ để đảm bảo tính tất định.
   */
  private async touchSessionActivityThrottled(
    userId: bigint,
    sessionId: string,
    ipAddress?: string,
  ): Promise<void> {
    if (typeof this.repository.touchSessionActivity !== 'function') {
      return;
    }
    const now = Date.now();
    const claimKey = `${sessionId}:${ipAddress ?? ''}`;
    const localExpiry = this.localTouchThrottle.get(claimKey);
    if (localExpiry !== undefined && localExpiry > now) {
      return;
    }
    this.setLocalTouchExpiry(claimKey, now + this.touchIntervalMs);

    const runTouch = async (): Promise<void> => {
      try {
        const claimed = await this.stateStore.claimOnce(
          'auth-session-touch',
          claimKey,
          this.touchIntervalMs,
          { failClosedInProd: false },
        );
        if (!claimed) {
          return;
        }
        await this.repository.touchSessionActivity(userId, sessionId, ipAddress);
      } catch {
        // Never block an authenticated request due to non-critical last_seen_at telemetry writes.
      }
    };

    const isRemote =
      typeof this.stateStore.hasRemoteRedis === 'function' && this.stateStore.hasRemoteRedis();
    if (isRemote) {
      void runTouch();
      return;
    }
    await runTouch();
  }

  /**
   * Thuật toán: Tra cứu `AuthPrincipal` 2 tầng L1 RAM (~0ms) -> L2 Redis 1-RTT `MGET` -> PostgreSQL,
   * tuyệt đối không lưu đệm `null` và tự xóa L1 tức thì ngay khi nhận sự kiện Pub/Sub thu hồi phiên/tài khoản.
   */
  private async resolveSessionPrincipal(
    userId: bigint,
    sessionId: string,
  ): Promise<AuthPrincipal | null> {
    const now = Date.now();
    const l1Hit = this.l1Sessions.get(sessionId);
    if (l1Hit && l1Hit.expiresAt > now && l1Hit.principal.userId === userId) {
      return l1Hit.principal;
    }
    if (l1Hit) {
      this.l1Sessions.delete(sessionId);
    }

    const generationBeforeLookup = this.generation;
    const userIdStr = userId.toString();
    let globalEpoch = 0;
    let userEpoch = 0;
    let cached: CachedAuthPrincipal | null = null;

    if (typeof this.stateStore.mgetBatch === 'function') {
      const [rawGlobal, rawUser, rawSession] = await this.stateStore.mgetBatch([
        { kind: 'epoch', namespace: 'auth-global' },
        { kind: 'epoch', namespace: `auth-user:${userIdStr}` },
        { kind: 'state', namespace: 'auth-session', id: sessionId },
      ]);
      globalEpoch = rawGlobal ? Number(rawGlobal) || 0 : 0;
      userEpoch = rawUser ? Number(rawUser) || 0 : 0;
      if (rawSession) {
        try {
          cached = JSON.parse(rawSession) as CachedAuthPrincipal;
        } catch {
          cached = null;
        }
      }
    } else {
      const [g, u, c] = await Promise.all([
        this.stateStore.getNamespaceEpoch('auth-global'),
        this.stateStore.getNamespaceEpoch(`auth-user:${userIdStr}`),
        this.stateStore.getJson<CachedAuthPrincipal>('auth-session', sessionId),
      ]);
      globalEpoch = g;
      userEpoch = u;
      cached = c;
    }

    if (
      cached &&
      cached.globalEpoch === globalEpoch &&
      cached.userEpoch === userEpoch &&
      cached.userId === userIdStr &&
      cached.sessionId === sessionId &&
      this.generation === generationBeforeLookup
    ) {
      const principal: AuthPrincipal = {
        userId: BigInt(cached.userId),
        sessionId: cached.sessionId,
        username: cached.username,
        roles: cached.roles,
        mfa: cached.mfa,
        mfaPending: cached.mfaPending,
        restrictedNonBusiness: cached.restrictedNonBusiness,
      };
      this.setL1Session(sessionId, principal, now + AUTH_SESSION_CACHE_TTL_MS);
      return principal;
    }

    const fresh = await this.repository.principalForSession(userId, sessionId);
    if (!fresh) {
      return null;
    }

    const payload: CachedAuthPrincipal = {
      userId: fresh.userId.toString(),
      sessionId: fresh.sessionId,
      username: fresh.username,
      roles: fresh.roles,
      mfa: fresh.mfa,
      mfaPending: fresh.mfaPending,
      restrictedNonBusiness: fresh.restrictedNonBusiness,
      userEpoch,
      globalEpoch,
    };

    // Thuật toán: Ghi đệm L2 Redis nguyên tử bằng Lua CAS `putEphemeralIfEpochsMatch` kết hợp đối chiếu thế hệ `generationBeforeLookup`
    // nhằm triệt tiêu hoàn toàn race condition ghi ngược phiên đã thu hồi / tài khoản đã khóa vào L1/L2 (HIGH-01).
    let written = false;
    if (this.generation === generationBeforeLookup) {
      try {
        if (typeof this.stateStore.putEphemeralIfEpochsMatch === 'function') {
          written = await this.stateStore.putEphemeralIfEpochsMatch({
            namespace: 'auth-session',
            id: sessionId,
            value: payload,
            ttlMs: AUTH_SESSION_CACHE_TTL_MS,
            expectedEpochs: [
              { namespace: 'auth-global', epoch: globalEpoch },
              { namespace: `auth-user:${userIdStr}`, epoch: userEpoch },
            ],
          });
        } else {
          const [curGlobal, curUser] = await Promise.all([
            this.stateStore.getNamespaceEpoch('auth-global'),
            this.stateStore.getNamespaceEpoch(`auth-user:${userIdStr}`),
          ]);
          if (
            curGlobal === globalEpoch &&
            curUser === userEpoch &&
            this.generation === generationBeforeLookup
          ) {
            await this.stateStore.putEphemeral<CachedAuthPrincipal>(
              'auth-session',
              sessionId,
              payload,
              AUTH_SESSION_CACHE_TTL_MS,
            );
            written = true;
          }
        }
      } catch {
        written = false;
      }
    }

    if (written && this.generation === generationBeforeLookup) {
      this.setL1Session(sessionId, fresh, Date.now() + AUTH_SESSION_CACHE_TTL_MS);
    } else {
      this.l1Sessions.delete(sessionId);
    }
    return fresh;
  }

  /** Thuật toán: Tăng `generation` và xóa tức thì mục đệm L1 bị ảnh hưởng khi nhận thông điệp vô hiệu hóa Epoch/Key qua Pub/Sub. */
  private handleCacheInvalidation(event: CacheInvalidationEvent): void {
    if (event.kind === 'key') {
      if (event.namespace === 'auth-session') {
        this.generation += 1;
        this.l1Sessions.delete(event.id);
      }
      return;
    }
    if (event.namespace === 'auth-global') {
      this.generation += 1;
      this.l1Sessions.clear();
      return;
    }
    if (event.namespace.startsWith('auth-user:')) {
      this.generation += 1;
      const targetUserId = event.namespace.slice('auth-user:'.length);
      for (const [sid, entry] of this.l1Sessions) {
        if (entry.principal.userId.toString() === targetUserId) {
          this.l1Sessions.delete(sid);
        }
      }
    }
  }

  private setL1Session(sessionId: string, principal: AuthPrincipal, expiresAt: number): void {
    if (!this.l1Sessions.has(sessionId) && this.l1Sessions.size >= MAX_L1_SESSIONS) {
      const now = Date.now();
      for (const [key, entry] of this.l1Sessions) {
        if (entry.expiresAt <= now) this.l1Sessions.delete(key);
      }
      if (this.l1Sessions.size >= MAX_L1_SESSIONS) {
        const oldest = this.l1Sessions.keys().next().value;
        if (oldest !== undefined) this.l1Sessions.delete(oldest);
      }
    }
    this.l1Sessions.set(sessionId, { principal, expiresAt });
  }

  private setLocalTouchExpiry(claimKey: string, expiresAt: number): void {
    if (
      !this.localTouchThrottle.has(claimKey) &&
      this.localTouchThrottle.size >= MAX_LOCAL_TOUCH_KEYS
    ) {
      const now = Date.now();
      for (const [key, exp] of this.localTouchThrottle) {
        if (exp <= now) this.localTouchThrottle.delete(key);
      }
      if (this.localTouchThrottle.size >= MAX_LOCAL_TOUCH_KEYS) {
        const oldest = this.localTouchThrottle.keys().next().value;
        if (oldest !== undefined) this.localTouchThrottle.delete(oldest);
      }
    }
    this.localTouchThrottle.set(claimKey, expiresAt);
  }
}
