/**
 * Algorithm: In-Memory Atomic Redis Redlock Node & Lua CAS Simulator
 * Description: Simulates a single independent Redis master node participating in the Redlock
 *              quorum protocol, supporting `SET key token PX ttl NX` mutual exclusion and atomic
 *              Lua compare-and-delete (`del`) / compare-and-extend (`pexpire`) token verification
 *              with injectable node network faults (`failNext`).
 * Time Complexity: O(1) per `set`, `eval`, or `ping` operation via hash map lookup.
 * Space Complexity: O(K) where K is the number of active lock keys held on the node.
 */
/**
 * Thuật toán: Mô phỏng Nút Redis Độc lập Cho Giao thức Khóa Phân tán Redlock (`MockRedisNode`)
 * Mục đích: Giả lập nguyên tử lệnh chiếm khóa `SET ... PX ttl NX` và kịch bản Lua so sánh-và-xóa (`del`) / so sánh-và-gia hạn (`pexpire`) kèm khả năng tiêm lỗi mạng (`failNext`).
 * Cơ chế hoạt động:
 *   - Lưu trữ cặp `{ value, expiresAt }` trên bảng băm `Map` trong bộ nhớ (`O(1)`); từ chối cấp khóa nếu khóa hiện hữu chưa hết hạn (`expiresAt > now`) và có cờ `NX`.
 *   - Trong `eval()`, chỉ cho phép giải phóng hoặc gia hạn khóa khi mã định danh chủ sở hữu `token` khớp chính xác với `entry.value` đang còn hiệu lực, ngăn chặn hiện tượng một tiến trình xóa nhầm khóa của tiến trình khác.
 */
export class MockRedisNode {
  constructor(name = 'node-1') {
    this.name = name;
    this.store = new Map();
    this.failNext = false;
  }

  async set(key, value, _px, ttl, nx) {
    if (this.failNext) {
      throw new Error(`Node ${this.name} connection error`);
    }
    const existing = this.store.get(key);
    const now = Date.now();
    if (existing && existing.expiresAt > now) {
      if (nx === 'NX') return null;
    }
    this.store.set(key, { value, expiresAt: now + ttl });
    return 'OK';
  }

  async eval(script, _numKeys, key, ...args) {
    if (this.failNext) {
      throw new Error(`Node ${this.name} connection error`);
    }
    const entry = this.store.get(key);
    const now = Date.now();
    const token = args[0];

    if (script.includes('del')) {
      if (entry && entry.expiresAt > now && entry.value === token) {
        this.store.delete(key);
        return 1;
      }
      return 0;
    }

    if (script.includes('pexpire')) {
      const additionalTtl = Number(args[1]);
      if (entry && entry.expiresAt > now && entry.value === token) {
        entry.expiresAt = now + additionalTtl;
        return 1;
      }
      return 0;
    }

    return 0;
  }

  async ping() {
    if (this.failNext) throw new Error('Unreachable');
    return 'PONG';
  }

  disconnect() {}
  on() {}
}

export function createMockConfig(overrides = {}) {
  const values = {
    REDIS_URL: 'redis://127.0.0.1:6379/0',
    REDLOCK_RETRY_COUNT: 2,
    REDLOCK_RETRY_DELAY_MS: 10,
    REDLOCK_RETRY_JITTER_MS: 5,
    REDLOCK_DEFAULT_TTL_MS: 2000,
    REDLOCK_FAIL_CLOSED: false,
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}
