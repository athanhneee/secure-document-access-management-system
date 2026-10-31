import {
  Controller,
  Get,
  Patch,
  Param,
  Query,
  Req,
  HttpStatus,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { QueryNotificationsSchema, UuidParamSchema } from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { NotificationsService } from './notifications.service.js';

@ApiTags('notifications')
@ApiBearerAuth()
@Controller('notifications')
export class NotificationsController {
  constructor(
    private readonly notificationsService: NotificationsService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  @RequirePermission('NOTIFICATION', 'VIEW')
  @ApiOperation({ summary: 'List in-app notifications for authenticated user' })
  @ApiResponse({ status: HttpStatus.OK, description: 'User notifications list' })
  async listMyNotifications(@Query() query: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    const parsed = QueryNotificationsSchema.safeParse(query);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.notificationsService.listUserNotifications(req.auth.userId, parsed.data);
  }

  @Patch(':id/read')
  @RequirePermission('NOTIFICATION', 'VIEW')
  @ApiOperation({ summary: 'Mark an in-app notification as read' })
  @ApiResponse({ status: HttpStatus.NO_CONTENT, description: 'Notification marked as read' })
  async markAsRead(@Param('id') id: string, @Req() req: FastifyRequest) {
    this.csrf.assertRequest(req);
    if (!req.auth) throw new UnauthorizedException('Authentication required.');
    const parsedId = UuidParamSchema.safeParse({ id });
    if (!parsedId.success) {
      throw new BadRequestException('Invalid notification UUID.');
    }
    await this.notificationsService.markAsRead(parsedId.data.id, req.auth.userId);
    return { success: true };
  }
}
