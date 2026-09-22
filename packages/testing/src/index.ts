import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import type { LivenessResponse } from '@sda/contracts';

export function assertLiveness(payload: unknown): asserts payload is LivenessResponse {
  assert.deepEqual(payload, { status: 'ok' });
}

export interface WaitForHttpOptions {
  readonly timeoutMs?: number;
  readonly intervalMs?: number;
}

/** Bounded readiness polling for local integration and end-to-end tests. */
export async function waitForHttp(
  url: string,
  options: WaitForHttpOptions = {},
): Promise<Response> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const intervalMs = options.intervalMs ?? 100;
  if (
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0 ||
    !Number.isFinite(intervalMs) ||
    intervalMs <= 0
  ) {
    throw new RangeError('Polling timeout and interval must be positive finite numbers.');
  }
  const deadline = performance.now() + timeoutMs;
  let lastError: unknown;
  while (performance.now() < deadline) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(Math.max(1, Math.ceil(deadline - performance.now()))),
      });
      if (response.ok) return response;
      lastError = new Error(`Unexpected readiness status: ${response.status}`);
      await response.body?.cancel();
    } catch (error) {
      lastError = error;
    }
    await delay(Math.max(0, Math.min(intervalMs, deadline - performance.now())));
  }
  throw new Error(`Service did not become ready within ${timeoutMs}ms.`, { cause: lastError });
}
