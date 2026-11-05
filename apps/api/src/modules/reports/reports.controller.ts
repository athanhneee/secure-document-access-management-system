/**
 * Module: ReportsController — Giao diện HTTP khởi tạo, tra cứu tiến độ và tải xuống báo cáo tuân thủ bất đồng bộ kèm tiêu đề cấm lưu đệm (`Cache-Control: no-store`).
 */
import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  BadRequestException,
  Header,
  Optional,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { CreateExportJobSchema } from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { resolveExportAuthorizationScope } from './export-filter-scope.helper.js';
import { ExportJobService } from './export-job.service.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Thuật toán: Kiểm tra định dạng UUID hợp lệ cho tham số đường dẫn `jobId`.
 */
function assertJobUuid(jobId: string): string {
  if (!UUID_REGEX.test(jobId)) {
    throw new BadRequestException('Export jobId must be a valid UUID.');
  }
  return jobId;
}

@ApiTags('reports')
@ApiBearerAuth()
@Controller('reports')
export class ReportsController {
  constructor(
    private readonly exportJobService: ExportJobService,
    private readonly csrf: CsrfService,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {}

  @Get('export')
  @ApiOperation({ summary: 'List recent asynchronous export jobs requested by current user' })
  @ApiResponse({ status: HttpStatus.OK, description: 'User export job history' })
  async listExportJobs(@Req() req: FastifyRequest) {
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    return this.exportJobService.listExportJobs(req.auth);
  }

  // CONFLICT-RESOLVED: Trả mã HTTP 202 Accepted chuẩn REST cho tác vụ xuất báo cáo bất đồng bộ (LOW-01)
  @Post('export')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Initiate an asynchronous report export job with 24h TTL' })
  @ApiResponse({ status: HttpStatus.ACCEPTED, description: 'Export job initiated' })
  async createExportJob(@Body() body: unknown, @Req() req: FastifyRequest) {
    this.csrf.assertRequest(req);
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    const parsed = CreateExportJobSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    await resolveExportAuthorizationScope(this.authorization, req.auth, parsed.data.exportType);
    return this.exportJobService.createExportJob(parsed.data, req.auth, req.correlationId);
  }

  @Get('export/:jobId')
  @ApiOperation({ summary: 'Check status and metadata of an export job' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Export job details' })
  async getExportJob(@Param('jobId') jobId: string, @Req() req: FastifyRequest) {
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    return this.exportJobService.getExportJob(assertJobUuid(jobId), req.auth);
  }

  @Get('export/:jobId/download')
  @Header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
  @Header('Pragma', 'no-cache')
  @ApiOperation({ summary: 'Download completed export report file' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Exported report file download' })
  async downloadExportJob(
    @Param('jobId') jobId: string,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ) {
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    const result = await this.exportJobService.downloadExportJob(assertJobUuid(jobId), req.auth);

    reply
      .header('Content-Type', result.mimeType)
      .header('Content-Disposition', `attachment; filename="${result.filename}"`)
      .send(result.buffer);
  }
}
