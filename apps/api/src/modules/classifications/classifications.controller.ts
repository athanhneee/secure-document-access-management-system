import { Controller, Get, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { ClassificationsService } from './classifications.service.js';

@ApiTags('classifications')
@ApiBearerAuth()
@Controller('classifications')
export class ClassificationsController {
  constructor(private readonly classificationsService: ClassificationsService) {}

  @Get('levels')
  @ApiOperation({ summary: 'List security classification levels' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Classification levels list' })
  async listClassificationLevels(): Promise<{ data: unknown[] }> {
    return this.classificationsService.listClassificationLevels();
  }

  @Get('categories')
  @ApiOperation({ summary: 'List business categories' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Business categories list' })
  async listBusinessCategories(): Promise<{ data: unknown[] }> {
    return this.classificationsService.listBusinessCategories();
  }
}
