import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Query,
  Body,
  Req,
  HttpStatus,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import {
  QuerySecurityAlertsSchema,
  UpdateAlertStatusSchema,
  AssignAlertSchema,
  AddAlertNoteSchema,
  CreateIncidentReportSchema,
  UpdateIncidentReportSchema,
  SubmitIncidentReportSchema,
  CloseIncidentReportSchema,
  CreateIncidentActionSchema,
  CompleteIncidentActionSchema,
  QueryIncidentReportsSchema,
  UpdateDetectionRuleConfigSchema,
  RunDetectionInputSchema,
} from '@sda/contracts';
import { RequirePermission } from '../rbac/require-permission.js';
import { SecurityAlertsService } from './security-alerts.service.js';
import { IncidentsService } from './incidents.service.js';
import { SecurityDetectionService } from './security-detection.service.js';

@ApiTags('security-operations')
@ApiBearerAuth()
@Controller()
export class SecurityOperationsController {
  constructor(
    private readonly alertsService: SecurityAlertsService,
    private readonly incidentsService: IncidentsService,
    private readonly detectionService: SecurityDetectionService,
  ) {}

  // --- Security Alerts Endpoints ---

  @Get('security-alerts')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List security alerts with filters and pagination' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Paginated security alerts list' })
  async listAlerts(@Query() query: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = QuerySecurityAlertsSchema.safeParse(query);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.alertsService.listAlerts(parsed.data);
  }

  @Get('security-alerts/:id')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({
    summary: 'Get security alert details by ID with linked audit logs and incidents',
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Security alert details' })
  async getAlertById(@Param('id') id: string, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    return this.alertsService.getAlertById(id);
  }

  @Patch('security-alerts/:id/status')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Update alert status with strict state machine validation' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated security alert' })
  async updateAlertStatus(
    @Param('id') id: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = UpdateAlertStatusSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.alertsService.updateAlertStatus(id, parsed.data, req.auth);
  }

  @Patch('security-alerts/:id/assign')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Assign security alert to an officer' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Assigned security alert' })
  async assignAlert(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = AssignAlertSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.alertsService.assignAlert(id, parsed.data.assignedToUserId, req.auth);
  }

  @Post('security-alerts/:id/notes')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Add investigation note to security alert' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated security alert with note' })
  async addAlertNote(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = AddAlertNoteSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.alertsService.addAlertNote(id, parsed.data.note, req.auth);
  }

  // --- Incident Reports Endpoints ---

  @Get('incidents')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List incident reports with filters and pagination' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Paginated incident reports list' })
  async listIncidents(@Query() query: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = QueryIncidentReportsSchema.safeParse(query);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.listIncidentReports(parsed.data);
  }

  @Get('incidents/:id')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'Get incident report details by ID' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Incident report details' })
  async getIncidentById(@Param('id') id: string, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    return this.incidentsService.getIncidentReportById(id);
  }

  @Post('incidents')
  @RequirePermission('INCIDENT_REPORT', 'CREATE')
  @ApiOperation({ summary: 'Create a new incident report in DRAFT status' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Created incident report' })
  async createIncident(@Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = CreateIncidentReportSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.createIncidentReport(parsed.data, req.auth);
  }

  @Patch('incidents/:id')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Update incident report details' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated incident report' })
  async updateIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = UpdateIncidentReportSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.updateIncidentReport(id, parsed.data, req.auth);
  }

  @Post('incidents/:id/submit')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Submit incident report to owner or administrator' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Submitted incident report' })
  async submitIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = SubmitIncidentReportSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.submitIncidentReport(id, parsed.data, req.auth);
  }

  @Post('incidents/:id/close')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Close incident report' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Closed incident report' })
  async closeIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = CloseIncidentReportSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.closeIncidentReport(id, parsed.data, req.auth);
  }

  @Post('incidents/:id/actions')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Add recommended action to incident report' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Created incident action' })
  async addIncidentAction(
    @Param('id') id: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = CreateIncidentActionSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.addIncidentAction(id, parsed.data, req.auth);
  }

  @Patch('incidents/:id/actions/:actionId/complete')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Complete an incident action with mandatory completion note' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Completed incident action' })
  async completeIncidentAction(
    @Param('actionId') actionId: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = CompleteIncidentActionSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.incidentsService.completeIncidentAction(BigInt(actionId), parsed.data, req.auth);
  }

  // --- Detection Rules Endpoints ---

  @Get('security-detection/rules')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List configurable anomaly detection rules' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Detection rules list' })
  async getDetectionRules(@Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    return this.detectionService.getRules();
  }

  @Patch('security-detection/rules/:ruleCode')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({
    summary: 'Configure anomaly detection rule parameters, threshold, window, cooldown',
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated detection rule' })
  async updateDetectionRule(
    @Param('ruleCode') ruleCode: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = UpdateDetectionRuleConfigSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    const updateData: Partial<import('./security-detection.service.js').DetectionRule> = {};
    if (parsed.data.isEnabled !== undefined) updateData.isEnabled = parsed.data.isEnabled;
    if (parsed.data.severity !== undefined) updateData.severity = parsed.data.severity;
    if (parsed.data.threshold !== undefined) updateData.threshold = parsed.data.threshold;
    if (parsed.data.windowMinutes !== undefined)
      updateData.windowMinutes = parsed.data.windowMinutes;
    if (parsed.data.cooldownMinutes !== undefined)
      updateData.cooldownMinutes = parsed.data.cooldownMinutes;
    if (parsed.data.parameters !== undefined) updateData.parameters = parsed.data.parameters;
    return this.detectionService.updateRule(ruleCode, updateData, req.auth.userId);
  }

  @Post('security-detection/run')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Manually trigger anomaly detection run' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Detection run results' })
  async runDetection(@Body() body: unknown, @Req() req: FastifyRequest) {
    if (!req.auth) throw new ForbiddenException('Authentication required.');
    const parsed = RunDetectionInputSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.detectionService.runAllDetections(parsed.data.windowMinutes);
  }
}
