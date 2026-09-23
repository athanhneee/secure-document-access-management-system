import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Req,
  Res,
  HttpStatus,
  ForbiddenException,
  BadRequestException,
  Header,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { CreateExportJobSchema } from '@sda/contracts';
import { RequirePermission } from '../rbac/require-permission.js';
import { ExportJobService } from './export-job.service.js';

@ApiTags('reports')
@ApiBearerAuth()
@Controller('reports')
export class ReportsController {
  constructor(private readonly exportJobService: ExportJobService) {}

  @Post('export')
  @RequirePermission('AUDIT_LOG', 'EXPORT')
  @ApiOperation({ summary: 'Initiate an asynchronous report export job with 24h TTL' })
  @ApiResponse({ status: HttpStatus.ACCEPTED, description: 'Export job initiated' })
  async createExportJob(@Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = CreateExportJobSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.exportJobService.createExportJob(parsed.data, req.auth);
  }

  @Get('export/:jobId')
  @RequirePermission('AUDIT_LOG', 'EXPORT')
  @ApiOperation({ summary: 'Check status and metadata of an export job' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Export job details' })
  async getExportJob(@Param('jobId') jobId: string, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    return this.exportJobService.getExportJob(jobId, req.auth);
  }

  @Get('export/:jobId/download')
  @RequirePermission('AUDIT_LOG', 'EXPORT')
  @Header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
  @Header('Pragma', 'no-cache')
  @ApiOperation({ summary: 'Download completed export report file' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Exported report file download' })
  async downloadExportJob(
    @Param('jobId') jobId: string,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const result = await this.exportJobService.downloadExportJob(jobId, req.auth);

    reply
      .header('Content-Type', result.mimeType)
      .header('Content-Disposition', `attachment; filename="${result.filename}"`)
      .send(result.buffer);
  }
}
