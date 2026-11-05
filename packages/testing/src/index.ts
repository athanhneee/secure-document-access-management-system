import assert from 'node:assert/strict';
import type { LivenessResponse } from '@sda/contracts';

/**
 * Algorithm / Thuật toán: Xác Thực Bất Biến Phản Hồi Sẵn Sàng Sống Còn (Strict Liveness Contract Assertion)
 * Mục đích: Đảm bảo phản hồi `/health/live` khớp chính xác cấu trúc bất biến `{ status: 'ok' }` không thừa/thiếu thuộc tính.
 */
export function assertLiveness(payload: unknown): asserts payload is LivenessResponse {
  assert.deepEqual(payload, { status: 'ok' });
}
