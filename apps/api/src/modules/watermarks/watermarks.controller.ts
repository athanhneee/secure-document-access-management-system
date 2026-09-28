import {
  Controller,
  Get,
  Patch,
  Body,
  HttpStatus,
  Param,
  Req,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { WatermarkTokenParamSchema } from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { WatermarksService, type WatermarkVerificationResult } from './watermarks.service.js';

@ApiTags('watermarks')
@ApiBearerAuth()
@Controller('watermarks')
export class WatermarksController {
  constructor(
    private readonly watermarksService: WatermarksService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('configs')
  @ApiOperation({ summary: 'List active watermark templates and configurations' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Watermark configurations list' })
  async listConfigs(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.watermarksService.listConfigs();
  }

  @Patch('configs/:id')
  @RequirePermission('WATERMARK_CONFIG', 'MANAGE', true)
  @ApiOperation({ summary: 'Update watermark configuration' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated watermark configuration' })
  async updateConfig(
    @Param('id') id: string,
    @Body() body: Parameters<WatermarksService['updateConfig']>[1],
    @Req() request: FastifyRequest,
  ): Promise<Record<string, unknown>> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    this.csrf.assertRequest(request);
    const idBigInt = BigInt(id);
    return this.watermarksService.updateConfig(idBigInt, body);
  }

  @Get('verify/:token')
  @RequirePermission('WATERMARK_INSTANCE', 'TRACE')
  @ApiOperation({
    summary: 'UC28: Reconcile watermark token to trace document leak provenance',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Watermark forensic provenance details',
  })
  async verifyWatermarkToken(
    @Param('token') token: string,
    @Req() request: FastifyRequest,
  ): Promise<WatermarkVerificationResult> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    const parsed = WatermarkTokenParamSchema.safeParse({ token });
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    return this.watermarksService.verifyWatermarkToken(parsed.data.token, request.auth);
  }
}
