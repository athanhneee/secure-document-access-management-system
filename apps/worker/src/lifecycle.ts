import { setTimeout as delay } from 'node:timers/promises';

/** Keep the scaffold alive without consuming jobs or accessing infrastructure. */
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
