import { Controller, Get, Post, Body, Header, HttpStatus, Res } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { PublicEndpoint } from '../../public-endpoint.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { HealthService } from './health.service.js';
import type { LivenessResponse, ReadinessResponse } from '@sda/contracts';

@ApiTags('system-health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

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
  async captureSnapshot(
    @Body() body: { serviceName: string; status: string; details?: Record<string, unknown> },
  ) {
    return this.healthService.captureBusinessSnapshot(
      body.serviceName,
      body.status,
      body.details ?? {},
    );
  }
}
