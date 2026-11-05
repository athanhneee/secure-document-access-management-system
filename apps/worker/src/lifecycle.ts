import { setTimeout as delay } from 'node:timers/promises';

/**
 * Thuật toán / Tổng quan module:
 * Quản lý vòng đời tiến trình nền dài hạn (Daemon Keep-Alive & Graceful Shutdown Waiter)
 * không chiếm dụng CPU (0% busy-wait) dựa trên hàng đợi sự kiện bất đồng bộ của Node.js và `AbortSignal`.
 */

/**
 * Keep the scaffold alive without consuming jobs or accessing infrastructure.
 *
 * Thuật toán: Treo tiến trình bất đồng bộ không bận chờ (Zero-Polling Event-Driven Suspension).
 * - Lặp ngủ theo chu kỳ tối đa số nguyên 32-bit có dấu (`2_147_483_647` ms ~ 24.85 ngày) gắn trực tiếp với `AbortSignal`.
 * - Ngay khi nhận tín hiệu dừng (`SIGINT`/`SIGTERM` -> `signal.aborted`), bắt ngoại lệ `AbortError` có kiểm soát và thoát hàm sạch sẽ.
 */
export async function waitForShutdown(signal: AbortSignal): Promise<void> {
  while (!signal.aborted) {
    try {
      await delay(2_147_483_647, undefined, { signal });
    } catch (error) {
      if (signal.aborted && error instanceof Error && error.name === 'AbortError') return;
      throw error;
    }
  }
}
