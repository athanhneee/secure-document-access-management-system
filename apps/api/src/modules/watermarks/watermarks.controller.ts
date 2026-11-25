/**
 * @module WatermarksController
 * Thuật toán: Điều phối API quản trị cấu hình watermark pháp y và truy vết nguồn rò rỉ tài liệu (UC28)
 * hỗ trợ cả mã đầy đủ 48-hex lẫn tiền tố hiển thị 12-hex với bảo vệ CSRF và kiểm tra quyền nguyên tử.
 */
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

  /**
   * Thuật toán: Chuẩn hóa tham số mã watermark (tự động bù tiền tố `WM-` nếu truyền chuỗi hex thuần 12..48 ký tự)
   * trước khi kiểm định lược đồ `WatermarkTokenParamSchema` và chuyển tiếp ngữ cảnh truy vết pháp chứng UC28.
   */
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
    const trimmed = typeof token === 'string' ? token.trim() : '';
    // CONFLICT-RESOLVED: Tự động chuẩn hóa chuỗi hex thuần 12..48 ký tự thành WM-<hex> chữ thường nhưng vẫn từ chối định dạng sai như 'WM-short' hoặc 'NOT-WM-ffff'.
    const candidateToken = /^[a-fA-F0-9]{12,48}$/u.test(trimmed)
      ? `WM-${trimmed.toLowerCase()}`
      : trimmed;
    const parsed = WatermarkTokenParamSchema.safeParse({ token: candidateToken });
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    return this.watermarksService.verifyWatermarkToken(parsed.data.token, request.auth, {
      ...(request.ip ? { ip: request.ip } : {}),
      userAgent:
        typeof request.headers?.['user-agent'] === 'string'
          ? request.headers['user-agent']
          : undefined,
      ...(request.correlationId ? { correlationId: request.correlationId } : {}),
    });
  }
}
