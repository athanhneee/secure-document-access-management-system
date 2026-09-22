import { Controller, Get, Param, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { DocumentsService } from './documents.service.js';

@ApiTags('documents')
@ApiBearerAuth()
@Controller('documents')
export class DocumentsController {
  constructor(private readonly documentsService: DocumentsService) {}

  @Get()
  @ApiOperation({ summary: 'Search and discover documents with server-side clearance filtering' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Documents discovery list' })
  listDocuments(): { data: unknown[] } {
    return this.documentsService.listDocuments();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get document metadata by ID' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Document metadata' })
  getDocumentById(@Param('id') id: string): { id: string } {
    return this.documentsService.getDocumentById(id);
  }
}
