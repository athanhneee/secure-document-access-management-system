/**
 * @module LoginRateLimitService
 * Bộ giới hạn tần suất đăng nhập hai chiều (IP & Tài khoản) sử dụng thuật toán cửa sổ trượt 15 phút
 * kết hợp độ trễ khóa lũy thừa có trần (Sliding-Window Exponential Backoff Rate Limiter).
 */
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';

interface AttemptState {
  failures: number;
  blockedUntil: number;
  lastFailure: number;
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
  // shortcut: 10,000 attempt states (~2 MB) per replica, move to Redis sliding-window Lua script for cluster-wide throttling
  private readonly states = new Map<string, AttemptState>();

  /**
   * Thuật toán: Tách khóa giới hạn tần suất an toàn cho proxy nội bộ (Proxy-Safe Composite Keying).
   * Mục đích: Với IP ngoại vi thực (`192.0.2.1`...), khóa trên cả `ip:<ip>` và `account:<key>` chống password spraying;
   *   với IP loopback/chưa phân giải (`127.0.0.1`, `::1`, `unknown`), ghép `ip:<ip>:account:<key>` để ngăn tấn công DoS
   *   khóa đăng nhập toàn hệ thống khi đứng sau reverse proxy cục bộ.
   */
  private resolveKeys(ip: string, accountKey: string): [string, string] {
    const ipKey = isLoopbackOrUnresolvedIp(ip) ? `ip:${ip}:account:${accountKey}` : `ip:${ip}`;
    return [ipKey, `account:${accountKey}`];
  }

  /**
   * Thuật toán: Kiểm tra khóa tạm thời trên hai khóa độc lập (`ip` và `account`).
   * Mục đích: Chặn sớm với HTTP 429 nếu bất kỳ chiều nào đang trong thời gian phạt `blockedUntil > now`.
   */
  assertAllowed(ip: string, accountKey: string, now = Date.now()): void {
    for (const key of this.resolveKeys(ip, accountKey)) {
      const state = this.states.get(key);
      if (state && state.blockedUntil > now) {
        throw new HttpException(
          'Authentication temporarily unavailable. Try again later.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
    }
  }

  /**
   * Thuật toán: Đếm lỗi cửa sổ trượt 15 phút kết hợp phạt trễ lũy thừa cơ số 2 (`min(5000ms, 250 * 2^(n-3))`).
   * Cơ chế hoạt động:
   *   1. Nếu lần thất bại trước cách hiện tại < 15 phút, tăng bộ đếm `failures`; ngược lại đặt lại về 1.
   *   2. Từ lần thất bại thứ 3 trở đi, áp thời gian chặn tăng gấp đôi mỗi lần (`250ms, 500ms, 1000ms...`) tối đa 5000ms.
   *   3. Lấy giá trị phạt lớn nhất giữa chiều IP và chiều tài khoản, đồng thời kích hoạt thu gom rác khi bảng vượt ngưỡng.
   */
  recordFailure(ip: string, accountKey: string, now = Date.now()): number {
    let delay = 0;
    for (const key of this.resolveKeys(ip, accountKey)) {
      const previous = this.states.get(key);
      const failures =
        previous && now - previous.lastFailure < 15 * 60_000 ? previous.failures + 1 : 1;
      const progressiveDelay = Math.min(5_000, failures < 3 ? 0 : 250 * 2 ** (failures - 3));
      this.states.set(key, {
        failures,
        blockedUntil: now + progressiveDelay,
        lastFailure: now,
      });
      delay = Math.max(delay, progressiveDelay);
    }
    this.prune(now);
    return delay;
  }

  /**
   * Thuật toán: Xóa trạng thái phạt của tài khoản sau khi xác thực thành công (giữ nguyên bộ đếm IP ngoại vi chống password spraying).
   */
  clearAccount(accountKey: string): void {
    this.states.delete(`account:${accountKey}`);
    const loopbackSuffix = `:account:${accountKey}`;
    for (const key of this.states.keys()) {
      if (key.startsWith('ip:') && key.endsWith(loopbackSuffix)) {
        this.states.delete(key);
      }
    }
  }

  /**
   * Thuật toán: Dọn dẹp bộ nhớ hai tầng theo ngưỡng dung lượng (Two-Tier TTL + FIFO Bounded-Capacity Eviction).
   * Cơ chế hoạt động: Khi số mục đạt >= 10.000, quét loại bỏ các khóa quá 30 phút; nếu vẫn chạm trần cứng 10.000 mục
   * (tấn công ngập lụt trong 30 phút), trục xuất các khóa cũ nhất theo thứ tự FIFO để bảo vệ tuyệt đối trần RAM.
   */
  private prune(now: number): void {
    if (this.states.size < 10_000) return;
    for (const [key, state] of this.states) {
      if (now - state.lastFailure > 30 * 60_000) this.states.delete(key);
    }
    while (this.states.size >= 10_000) {
      const oldestKey = this.states.keys().next().value;
      if (!oldestKey) break;
      this.states.delete(oldestKey);
    }
  }
}
