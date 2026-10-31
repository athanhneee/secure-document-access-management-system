import { timingSafeEqual } from 'node:crypto';
import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  Header,
  HttpStatus,
  Optional,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppConfigService } from '../../config/config.service.js';
import { PublicEndpoint } from '../../public-endpoint.js';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { HealthService } from './health.service.js';
import { MetricsService } from './metrics.service.js';
import type { LivenessResponse, ReadinessResponse } from '@sda/contracts';

const CaptureSnapshotSchema = z
  .object({
    serviceName: z
      .string()
      .trim()
      .min(1)
      .max(64)
      .regex(/^[a-zA-Z0-9._-]+$/),
    status: z.enum(['HEALTHY', 'DEGRADED', 'UNHEALTHY', 'OK', 'ERROR']),
    details: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

function isPrivateOrLoopbackIp(rawIp: string | undefined): boolean {
  if (!rawIp) return false;
  const ip = rawIp.startsWith('::ffff:') ? rawIp.slice(7) : rawIp;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  const match172 = /^172\.(\d{1,3})\./.exec(ip);
  if (match172 && match172[1]) {
    const secondOctet = Number.parseInt(match172[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  return false;
}

@ApiTags('system-health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly healthService: HealthService,
    private readonly metricsService: MetricsService,
    @Optional() private readonly csrf?: CsrfService,
    @Optional() private readonly config?: AppConfigService,
  ) {}

  @Get('metrics')
  @PublicEndpoint()
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  @Header('Cache-Control', 'no-store')
  @ApiOperation({ summary: 'Prometheus metrics scrape endpoint' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Prometheus text format metrics' })
  async getMetrics(@Req() request?: FastifyRequest): Promise<string> {
    this.assertMetricsAccess(request);
    try {
      const live = await this.healthService.getLiveMetrics();
      this.metricsService.setActiveSessions(live.operational.activeSessionsCount);
      this.metricsService.setQueueDepth('export', live.operational.pendingExportsCount);
    } catch {
      // In degraded state, export available in-memory metrics
    }
    return this.metricsService.exportPrometheusText();
  }

  @Get('live')
  @PublicEndpoint()
  @Header('Cache-Control', 'no-store')
  @Header('X-Content-Type-Options', 'nosniff')
  @ApiOperation({ summary: 'Liveness probe confirming API process availability' })
  @ApiResponse({ status: HttpStatus.OK, description: 'API process is alive' })
  getLiveness(): LivenessResponse {
    return this.healthService.checkLiveness();
  }

  @Get('ready')
  @PublicEndpoint()
  @Header('Cache-Control', 'no-store')
  @Header('X-Content-Type-Options', 'nosniff')
  @ApiOperation({ summary: 'Readiness probe checking database, redis, and storage dependencies' })
  @ApiResponse({ status: HttpStatus.OK, description: 'All core dependencies are healthy' })
  @ApiResponse({
    status: HttpStatus.SERVICE_UNAVAILABLE,
    description: 'One or more dependencies are down',
  })
  async getReadiness(@Res({ passthrough: true }) reply: FastifyReply): Promise<ReadinessResponse> {
    const { isReady, response } = await this.healthService.checkReadiness();
    if (!isReady) {
      reply.status(HttpStatus.SERVICE_UNAVAILABLE);
    }
    return response;
  }

  @Get('dashboard')
  @RequirePermission('SYSTEM_HEALTH', 'VIEW')
  @Header('Cache-Control', 'no-store')
  @ApiOperation({ summary: 'Operational metrics dashboard reading live runtime metrics' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Live operational metrics' })
  async getDashboard() {
    return this.healthService.getLiveMetrics();
  }

  @Get('snapshots')
  @RequirePermission('SYSTEM_HEALTH', 'VIEW')
  @Header('Cache-Control', 'no-store')
  @ApiOperation({ summary: 'Historical business health snapshots' })
  @ApiResponse({ status: HttpStatus.OK, description: 'List of business snapshots' })
  async getSnapshots() {
    return this.healthService.listBusinessSnapshots();
  }

  @Post('snapshots')
  @RequirePermission('SYSTEM_HEALTH', 'VIEW')
  @ApiOperation({ summary: 'Capture an operational business snapshot for audit history' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Captured business snapshot' })
  async captureSnapshot(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf?.assertRequest(request);
    if (!request?.auth) {
      throw new UnauthorizedException('Authentication context is unavailable.');
    }
    const parsed = CaptureSnapshotSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException('Invalid snapshot payload.');
    }
    const details = parsed.data.details ?? {};
    if (JSON.stringify(details).length > 4096) {
      throw new BadRequestException('Snapshot details payload exceeds maximum allowed size.');
    }
    return this.healthService.captureBusinessSnapshot(parsed.data.serviceName, parsed.data.status, {
      ...details,
      capturedByUserId: String(request.auth.userId),
    });
  }

  private assertMetricsAccess(request?: FastifyRequest): void {
    if (!request) return;
    const scrapeToken = this.config?.get('METRICS_SCRAPE_TOKEN');
    if (scrapeToken) {
      const authHeader = request.headers?.['authorization'];
      const presented =
        typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
          ? authHeader.slice(7).trim()
          : '';
      const expectedBuf = Buffer.from(scrapeToken, 'utf8');
      const presentedBuf = Buffer.from(presented, 'utf8');
      if (
        expectedBuf.length !== presentedBuf.length ||
        !timingSafeEqual(expectedBuf, presentedBuf)
      ) {
        throw new UnauthorizedException('Valid metrics scrape token is required.');
      }
      return;
    }

    if (this.config?.isProduction && !isPrivateOrLoopbackIp(request.ip)) {
      throw new ForbiddenException(
        'Metrics scraping requires METRICS_SCRAPE_TOKEN or internal scraper network.',
      );
    }
  }
}
