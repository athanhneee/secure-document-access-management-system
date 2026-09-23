import {
  Controller,
  Get,
  Patch,
  Param,
  Query,
  Req,
  HttpStatus,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { QueryNotificationsSchema } from '@sda/contracts';
import { NotificationsService } from './notifications.service.js';

@ApiTags('notifications')
@ApiBearerAuth()
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  @ApiOperation({ summary: 'List in-app notifications for authenticated user' })
  @ApiResponse({ status: HttpStatus.OK, description: 'User notifications list' })
  async listMyNotifications(@Query() query: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = QueryNotificationsSchema.safeParse(query);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.notificationsService.listUserNotifications(req.auth.userId, parsed.data);
  }

  @Patch(':id/read')
  @ApiOperation({ summary: 'Mark an in-app notification as read' })
  @ApiResponse({ status: HttpStatus.NO_CONTENT, description: 'Notification marked as read' })
  async markAsRead(@Param('id') id: string, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    await this.notificationsService.markAsRead(id, req.auth.userId);
    return { success: true };
  }
}
