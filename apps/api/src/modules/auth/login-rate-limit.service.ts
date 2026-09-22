import { HttpException, HttpStatus, Injectable } from '@nestjs/common';

interface AttemptState {
  failures: number;
  blockedUntil: number;
  lastFailure: number;
}

@Injectable()
export class LoginRateLimitService {
  private readonly states = new Map<string, AttemptState>();

  assertAllowed(ip: string, accountKey: string, now = Date.now()): void {
    for (const key of [`ip:${ip}`, `account:${accountKey}`]) {
      const state = this.states.get(key);
      if (state && state.blockedUntil > now) {
        throw new HttpException(
          'Authentication temporarily unavailable. Try again later.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
    }
  }

  recordFailure(ip: string, accountKey: string, now = Date.now()): number {
    let delay = 0;
    for (const key of [`ip:${ip}`, `account:${accountKey}`]) {
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

  clearAccount(accountKey: string): void {
    this.states.delete(`account:${accountKey}`);
  }

  private prune(now: number): void {
    if (this.states.size < 10_000) return;
    for (const [key, state] of this.states) {
      if (now - state.lastFailure > 30 * 60_000) this.states.delete(key);
    }
  }
}
