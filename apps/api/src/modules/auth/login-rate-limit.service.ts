/**
 * @module LoginRateLimitService
 * Thuật toán: Bộ giới hạn tần suất đăng nhập hai chiều (IP & Tài khoản) phân tán xuyên bản sao qua `DistributedStateService`
 * sử dụng cửa sổ 15 phút (`incrementWindowCounter`) kết hợp khóa trễ lũy thừa có trần (`min(5000ms, 250 * 2^(n-3))`).
 */
import { HttpException, HttpStatus, Injectable, Optional } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';

const LOGIN_WINDOW_MS = 15 * 60_000;

function resolveMaxLoginDelayMs(): number {
  const configured = Number(process.env['LOGIN_RATE_LIMIT_MAX_DELAY_MS']);
  if (Number.isFinite(configured) && configured >= 1_000 && configured <= 300_000) {
    return Math.trunc(configured);
  }
  return process.env['NODE_ENV'] === 'test' ? 5_000 : 30_000;
}

interface BlockState {
  blockedUntil: number;
}

function isLoopbackOrUnresolvedIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase();
  return (
    normalized.length === 0 ||
    normalized === 'unknown' ||
    normalized === '::1' ||
    normalized.startsWith('127.') ||
    normalized.startsWith('::ffff:127.')
  );
}

export type AuthRateLimitScope = 'login' | 'change-password' | 'forgot-password' | 'mfa';

interface RateLimitNamespaces {
  epochPrefix: string;
  counterNamespace: string;
  blockNamespace: string;
}

/**
 * Thuật toán: Cô lập không gian tên bộ đếm & khóa tạm thời theo luồng xác thực (`login`, `change-password`, `forgot-password`, BUG-107)
 * để yêu cầu quên mật khẩu / đổi mật khẩu trên mạng văn phòng NAT chung không bao giờ cộng dồn khóa đăng nhập `login-failures`.
 */
function resolveScopeNamespaces(scope: AuthRateLimitScope): RateLimitNamespaces {
  if (scope === 'login') {
    return {
      epochPrefix: 'login-acct',
      counterNamespace: 'login-failures',
      blockNamespace: 'login-block',
    };
  }
  return {
    epochPrefix: `auth-acct:${scope}`,
    counterNamespace: `auth-failures:${scope}`,
    blockNamespace: `auth-block:${scope}`,
  };
}

@Injectable()
export class LoginRateLimitService {
  private readonly stateStore: DistributedStateService;

  constructor(
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.stateStore = stateStore ?? new DistributedStateService(config);
  }

  /**
   * Thuật toán: Tách khóa giới hạn tần suất an toàn cho proxy nội bộ kết hợp số hiệu thế hệ tài khoản (`Epoch Versioning`).
   *   - Với IP ngoại vi thực (`192.0.2.1`...): khóa trên `ip:<ip>` và `account:<key>:e<epoch>` trong không gian tên của từng `scope`.
   *   - Với IP loopback (`127.0.0.1`, `::1`, `unknown`): ghép `ip:<ip>:account:<key>:e<epoch>` chống DoS toàn hệ thống.
   */
  private async resolveKeys(
    ip: string,
    accountKey: string,
    scope: AuthRateLimitScope,
  ): Promise<{ keys: [string, string]; namespaces: RateLimitNamespaces }> {
    const namespaces = resolveScopeNamespaces(scope);
    const accountEpoch = await this.stateStore.getNamespaceEpoch(
      `${namespaces.epochPrefix}:${accountKey}`,
    );
    const scopedAccountKey = `account:${accountKey}:e${accountEpoch}`;
    const ipKey = isLoopbackOrUnresolvedIp(ip)
      ? `ip:${ip}:account:${accountKey}:e${accountEpoch}`
      : `ip:${ip}`;
    return { keys: [ipKey, scopedAccountKey], namespaces };
  }

  /**
   * Thuật toán: Kiểm tra khóa tạm thời trên hai chiều độc lập (`ip` và `account`) theo `scope` qua `mgetBatch` gộp 1-RTT khi khả dụng.
   */
  async assertAllowed(
    ip: string,
    accountKey: string,
    nowOrScope: number | AuthRateLimitScope = Date.now(),
    scopeArg: AuthRateLimitScope = 'login',
  ): Promise<void> {
    const now = typeof nowOrScope === 'number' ? nowOrScope : Date.now();
    const scope = typeof nowOrScope === 'string' ? nowOrScope : scopeArg;
    const { keys, namespaces } = await this.resolveKeys(ip, accountKey, scope);
    let blocks: Array<BlockState | null>;
    if (typeof this.stateStore.mgetBatch === 'function') {
      const rawValues = await this.stateStore.mgetBatch(
        keys.map((id) => ({ kind: 'state' as const, namespace: namespaces.blockNamespace, id })),
      );
      blocks = rawValues.map((raw) => {
        if (!raw) return null;
        try {
          return JSON.parse(raw) as BlockState;
        } catch {
          return null;
        }
      });
    } else {
      blocks = await Promise.all(
        keys.map((key) => this.stateStore.getJson<BlockState>(namespaces.blockNamespace, key)),
      );
    }
    if (blocks.some((state) => state !== null && state.blockedUntil > now)) {
      throw new HttpException(
        'Authentication temporarily unavailable. Try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  /**
   * Thuật toán: Tăng nguyên tử bộ đếm lỗi cửa sổ 15 phút (`incrementWindowCounter`) theo `scope` và áp phạt trễ lũy thừa cơ số 2 (`min(5000ms, 250 * 2^(n-3))`).
   */
  async recordFailure(
    ip: string,
    accountKey: string,
    nowOrScope: number | AuthRateLimitScope = Date.now(),
    scopeArg: AuthRateLimitScope = 'login',
  ): Promise<number> {
    const now = typeof nowOrScope === 'number' ? nowOrScope : Date.now();
    const scope = typeof nowOrScope === 'string' ? nowOrScope : scopeArg;
    const { keys, namespaces } = await this.resolveKeys(ip, accountKey, scope);
    let delay = 0;
    for (const key of keys) {
      const { count } = await this.stateStore.incrementWindowCounter(
        namespaces.counterNamespace,
        key,
        LOGIN_WINDOW_MS,
      );
      const maxDelayMs = resolveMaxLoginDelayMs();
      const progressiveDelay = Math.min(maxDelayMs, count < 3 ? 0 : 250 * 2 ** (count - 3));
      if (progressiveDelay > 0) {
        await this.stateStore.putEphemeral<BlockState>(
          namespaces.blockNamespace,
          key,
          { blockedUntil: now + progressiveDelay },
          Math.max(progressiveDelay, 5_000),
        );
      }
      delay = Math.max(delay, progressiveDelay);
    }
    return delay;
  }

  /**
   * Thuật toán: Xóa trạng thái phạt của tài khoản trên mọi bản sao trong đúng 1 vòng RTT Lua (`bumpNamespaceEpoch`) theo `scope`.
   */
  async clearAccount(accountKey: string, scope: AuthRateLimitScope = 'login'): Promise<void> {
    const { epochPrefix } = resolveScopeNamespaces(scope);
    await this.stateStore.bumpNamespaceEpoch(`${epochPrefix}:${accountKey}`);
  }
}
