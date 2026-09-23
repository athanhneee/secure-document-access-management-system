import { Injectable } from '@nestjs/common';
import * as net from 'node:net';
import { getDatabaseClient } from '@sda/database';
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

  /**
   * Reads real-time runtime system operational metrics.
   * Note: Does not use snapshot table to replace time-series monitoring.
   */
  async getLiveMetrics() {
    const memory = process.memoryUsage();
    const uptimeSeconds = Math.floor(process.uptime());
    const db = this.getDb();

    let activeSessionsCount = 0;
    let openAlertsCount = 0;
    let pendingExportsCount = 0;

    if (db) {
      try {
        const [activeSessions, openAlerts, pendingExports] = await Promise.all([
          db.accessSession.count({ where: { status: 'ACTIVE' } }),
          db.securityAlert.count({ where: { status: { in: ['OPEN', 'INVESTIGATING'] } } }),
          db.asyncExportJob.count({ where: { status: 'PENDING' } }),
        ]);
        activeSessionsCount = activeSessions;
        openAlertsCount = openAlerts;
        pendingExportsCount = pendingExports;
      } catch {
        // Handle gracefully if database is in degraded state
      }
    }

    const { isReady, response } = await this.checkReadiness();

    return {
      timestamp: new Date().toISOString(),
      process: {
        uptimeSeconds,
        heapUsedMb: Math.round((memory.heapUsed / 1024 / 1024) * 100) / 100,
        heapTotalMb: Math.round((memory.heapTotal / 1024 / 1024) * 100) / 100,
        rssMb: Math.round((memory.rss / 1024 / 1024) * 100) / 100,
      },
      operational: {
        activeSessionsCount,
        openAlertsCount,
        pendingExportsCount,
      },
      dependencies: {
        isReady,
        checks: response.checks,
      },
    };
  }

  /**
   * Captures a business snapshot purely for historical audit records.
   */
  async captureBusinessSnapshot(
    serviceName: string,
    status: string,
    details: Record<string, unknown> = {},
  ) {
    const db = this.getDb();
    if (!db) return null;

    return db.systemHealthSnapshot.create({
      data: {
        service_name: serviceName,
        status,
        response_time_ms: 10,
        error_count: 0,
        details: details as never,
      },
    });
  }

  /**
   * Retrieves historical business snapshots.
   */
  async listBusinessSnapshots(limit = 20) {
    const db = this.getDb();
    if (!db) return [];

    const items = await db.systemHealthSnapshot.findMany({
      take: limit,
      orderBy: { captured_at: 'desc' },
    });

    return items.map((s) => ({
      id: s.id.toString(),
      capturedAt: s.captured_at.toISOString(),
      serviceName: s.service_name,
      status: s.status,
      responseTimeMs: s.response_time_ms,
      errorCount: s.error_count,
      details: s.details,
    }));
  }

  private getDb() {
    try {
      return getDatabaseClient();
    } catch {
      return null;
    }
  }
}
