import { Controller, Get, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { WatermarksService } from './watermarks.service.js';

@ApiTags('watermarks')
@ApiBearerAuth()
@Controller('watermarks')
export class WatermarksController {
  constructor(private readonly watermarksService: WatermarksService) {}

  @Get('configs')
  @ApiOperation({ summary: 'List active watermark templates and configurations' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Watermark configurations list' })
  listConfigs(): { data: unknown[] } {
    return this.watermarksService.listConfigs();
  }
}
