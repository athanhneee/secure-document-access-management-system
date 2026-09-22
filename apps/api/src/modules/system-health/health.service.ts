import { Injectable } from '@nestjs/common';
import * as net from 'node:net';
import { AppConfigService } from '../../config/config.service.js';
import type { DependencyHealth, LivenessResponse, ReadinessResponse } from '@sda/contracts';

@Injectable()
export class HealthService {
  constructor(private readonly configService: AppConfigService) {}

  checkLiveness(): LivenessResponse {
    return { status: 'ok' };
  }

  async checkReadiness(): Promise<{ isReady: boolean; response: ReadinessResponse }> {
    const timestamp = new Date().toISOString();
    const timeoutMs = 2_000;

    const [database, redis, storage] = await Promise.all([
      this.probeDatabase(timeoutMs),
      this.probeRedis(timeoutMs),
      this.probeStorage(timeoutMs),
    ]);

    const isReady = database.status === 'up' && redis.status === 'up' && storage.status === 'up';

    const response: ReadinessResponse = {
      status: isReady ? 'ready' : 'degraded',
      timestamp,
      checks: {
        database,
        redis,
        storage,
      },
    };

    return { isReady, response };
  }

  private async probeDatabase(timeoutMs: number): Promise<DependencyHealth> {
    const start = Date.now();
    try {
      const dbUrl = this.configService.get('DATABASE_URL');
      const url = new URL(dbUrl);
      const host = url.hostname;
      const port = Number(url.port || 5432);

      await this.tcpPing(host, port, timeoutMs);
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      // NEVER leak connection credentials or stack traces
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Database service is unreachable or timed out',
      };
    }
  }

  private async probeRedis(timeoutMs: number): Promise<DependencyHealth> {
    const start = Date.now();
    try {
      const redisUrl = this.configService.get('REDIS_URL');
      const url = new URL(redisUrl);
      const host = url.hostname;
      const port = Number(url.port || 6379);

      await this.tcpPing(host, port, timeoutMs);
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      // NEVER leak connection credentials or stack traces
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Redis service is unreachable or timed out',
      };
    }
  }

  private async probeStorage(timeoutMs: number): Promise<DependencyHealth> {
    const start = Date.now();
    try {
      const host = this.configService.get('STORAGE_ENDPOINT');
      const port = this.configService.get('STORAGE_PORT');
      const protocol = this.configService.get('STORAGE_USE_SSL') ? 'https' : 'http';
      const response = await fetch(`${protocol}://${host}:${port}/minio/health/ready`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      await response.body?.cancel();
      if (!response.ok) throw new Error('Storage readiness endpoint is not healthy');
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      // NEVER leak storage keys or credentials
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Object storage service is unreachable or timed out',
      };
    }
  }

  private tcpPing(host: string, port: number, timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let hasTimedOut = false;

      socket.setTimeout(timeoutMs);
      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });

      socket.once('timeout', () => {
        hasTimedOut = true;
        socket.destroy();
        reject(new Error('Connection timed out'));
      });

      socket.once('error', (err) => {
        if (!hasTimedOut) {
          socket.destroy();
          reject(err);
        }
      });

      socket.connect(port, host);
    });
  }
}
