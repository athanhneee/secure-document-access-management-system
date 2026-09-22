import { Controller, Get, Header, HttpStatus, Res } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { PublicEndpoint } from '../../public-endpoint.js';
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
}
