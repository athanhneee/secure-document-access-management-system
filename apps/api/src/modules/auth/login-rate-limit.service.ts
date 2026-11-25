/**
 * @module LoginRateLimitService
 * Thuật toán: Bộ giới hạn tần suất đăng nhập hai chiều (IP & Tài khoản) phân tán xuyên bản sao qua `DistributedStateService`
 * sử dụng cửa sổ 15 phút (`incrementWindowCounter`) kết hợp khóa trễ lũy thừa có trần (`min(5000ms, 250 * 2^(n-3))`).
 */
import { HttpException, HttpStatus, Injectable, Optional } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';

const LOGIN_WINDOW_MS = 15 * 60_000;

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
   *   - Với IP ngoại vi thực (`192.0.2.1`...): khóa trên `ip:<ip>` và `account:<key>:e<epoch>` chống password spraying.
   *   - Với IP loopback (`127.0.0.1`, `::1`, `unknown`): ghép `ip:<ip>:account:<key>:e<epoch>` chống DoS toàn hệ thống.
   */
  private async resolveKeys(ip: string, accountKey: string): Promise<[string, string]> {
    const accountEpoch = await this.stateStore.getNamespaceEpoch(`login-acct:${accountKey}`);
    const scopedAccountKey = `account:${accountKey}:e${accountEpoch}`;
    const ipKey = isLoopbackOrUnresolvedIp(ip)
      ? `ip:${ip}:account:${accountKey}:e${accountEpoch}`
      : `ip:${ip}`;
    return [ipKey, scopedAccountKey];
  }

  /**
   * Thuật toán: Kiểm tra khóa tạm thời trên hai chiều độc lập (`ip` và `account`) qua `mgetBatch` gộp 1-RTT khi khả dụng.
   */
  async assertAllowed(ip: string, accountKey: string, now = Date.now()): Promise<void> {
    const keys = await this.resolveKeys(ip, accountKey);
    let blocks: Array<BlockState | null>;
    if (typeof this.stateStore.mgetBatch === 'function') {
      const rawValues = await this.stateStore.mgetBatch(
        keys.map((id) => ({ kind: 'state' as const, namespace: 'login-block', id })),
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
        keys.map((key) => this.stateStore.getJson<BlockState>('login-block', key)),
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
   * Thuật toán: Tăng nguyên tử bộ đếm lỗi cửa sổ 15 phút (`incrementWindowCounter`) và áp phạt trễ lũy thừa cơ số 2 (`min(5000ms, 250 * 2^(n-3))`).
   */
  async recordFailure(ip: string, accountKey: string, now = Date.now()): Promise<number> {
    const keys = await this.resolveKeys(ip, accountKey);
    let delay = 0;
    for (const key of keys) {
      const { count } = await this.stateStore.incrementWindowCounter(
        'login-failures',
        key,
        LOGIN_WINDOW_MS,
      );
      const progressiveDelay = Math.min(5_000, count < 3 ? 0 : 250 * 2 ** (count - 3));
      if (progressiveDelay > 0) {
        await this.stateStore.putEphemeral<BlockState>(
          'login-block',
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
   * Thuật toán: Xóa trạng thái phạt của tài khoản trên mọi bản sao trong đúng 1 vòng RTT Lua (`bumpNamespaceEpoch`),
   * không còn tốn vòng đọc trước `getNamespaceEpoch` hay 2 lệnh `DEL` dư thừa vì khóa tài khoản gắn hậu tố `:e<epoch>`.
   */
  async clearAccount(accountKey: string): Promise<void> {
    await this.stateStore.bumpNamespaceEpoch(`login-acct:${accountKey}`);
  }
}
