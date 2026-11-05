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
import { z } from 'zod';
import { PositiveBigIntSchema, WatermarkTokenParamSchema } from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { WatermarksService, type WatermarkVerificationResult } from './watermarks.service.js';

const WatermarkConfigIdSchema = PositiveBigIntSchema;

const UpdateWatermarkConfigSchema = z
  .object({
    opacityPercent: z.number().min(10).max(90).optional(),
    fontSize: z.number().min(8).max(72).optional(),
    includeQrCode: z.boolean().optional(),
    colorHex: z
      .string()
      .regex(/^#[0-9A-Fa-f]{6}$/u)
      .optional(),
    rotationDegrees: z.number().min(-90).max(90).optional(),
    templateText: z.string().trim().min(5).max(250).optional(),
    isVisible: z.literal(true).optional(),
  })
  .strict();

@ApiTags('watermarks')
@ApiBearerAuth()
@Controller('watermarks')
export class WatermarksController {
  constructor(
    private readonly watermarksService: WatermarksService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('configs')
  @RequirePermission('WATERMARK_CONFIG', 'MANAGE', true)
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
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<Record<string, unknown>> {
    this.csrf.assertRequest(request);
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    const parsedId = WatermarkConfigIdSchema.safeParse(id);
    if (!parsedId.success) {
      throw new BadRequestException('Invalid watermark configuration ID.');
    }
    const parsedBody = UpdateWatermarkConfigSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }
    return this.watermarksService.updateConfig(
      parsedId.data,
      parsedBody.data as Parameters<WatermarksService['updateConfig']>[1],
      request.auth,
    );
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
