import { Controller, Get, Post, Patch, Param, Query, Body, Req, HttpStatus } from '@nestjs/common';
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
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { SecurityAlertsService } from './security-alerts.service.js';
import { IncidentsService } from './incidents.service.js';
import { SecurityDetectionService } from './security-detection.service.js';
import {
  parseActionIdParam,
  parseUuidParam,
  parseZodPayload,
  requireAuthenticatedPrincipal,
  requireMutatingPrincipal,
  toDetectionRulePatch,
} from './security-operations-controller.helper.js';

@ApiTags('security-operations')
@ApiBearerAuth()
@Controller()
export class SecurityOperationsController {
  constructor(
    private readonly alertsService: SecurityAlertsService,
    private readonly incidentsService: IncidentsService,
    private readonly detectionService: SecurityDetectionService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('security-alerts')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List security alerts with filters and pagination' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Paginated security alerts list' })
  async listAlerts(@Query() query: unknown, @Req() req: FastifyRequest) {
    const auth = requireAuthenticatedPrincipal(req);
    return this.alertsService.listAlerts(parseZodPayload(QuerySecurityAlertsSchema, query), auth);
  }

  @Get('security-alerts/:id')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({
    summary: 'Get security alert details by ID with linked audit logs and incidents',
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Security alert details' })
  async getAlertById(@Param('id') id: string, @Req() req: FastifyRequest) {
    const auth = requireAuthenticatedPrincipal(req);
    return this.alertsService.getAlertById(parseUuidParam(id, 'alert'), auth);
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
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.alertsService.updateAlertStatus(
      parseUuidParam(id, 'alert'),
      parseZodPayload(UpdateAlertStatusSchema, body),
      auth,
    );
  }

  @Patch('security-alerts/:id/assign')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Assign security alert to an officer' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Assigned security alert' })
  async assignAlert(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    const data = parseZodPayload(AssignAlertSchema, body);
    return this.alertsService.assignAlert(parseUuidParam(id, 'alert'), data.assignedToUserId, auth);
  }

  @Post('security-alerts/:id/notes')
  @RequirePermission('SECURITY_ALERT', 'MANAGE')
  @ApiOperation({ summary: 'Add investigation note to security alert' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated security alert with note' })
  async addAlertNote(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    const data = parseZodPayload(AddAlertNoteSchema, body);
    return this.alertsService.addAlertNote(parseUuidParam(id, 'alert'), data.note, auth);
  }

  @Get('incidents')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List incident reports with filters and pagination' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Paginated incident reports list' })
  async listIncidents(@Query() query: unknown, @Req() req: FastifyRequest) {
    const auth = requireAuthenticatedPrincipal(req);
    return this.incidentsService.listIncidentReports(
      parseZodPayload(QueryIncidentReportsSchema, query),
      auth,
    );
  }

  @Get('incidents/:id')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'Get incident report details by ID' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Incident report details' })
  async getIncidentById(@Param('id') id: string, @Req() req: FastifyRequest) {
    const auth = requireAuthenticatedPrincipal(req);
    return this.incidentsService.getIncidentReportById(parseUuidParam(id, 'incident'), auth);
  }

  @Post('incidents')
  @RequirePermission('INCIDENT_REPORT', 'CREATE')
  @ApiOperation({ summary: 'Create a new incident report in DRAFT status' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Created incident report' })
  async createIncident(@Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.createIncidentReport(
      parseZodPayload(CreateIncidentReportSchema, body),
      auth,
    );
  }

  @Patch('incidents/:id')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Update incident report details' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated incident report' })
  async updateIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.updateIncidentReport(
      parseUuidParam(id, 'incident'),
      parseZodPayload(UpdateIncidentReportSchema, body),
      auth,
    );
  }

  @Post('incidents/:id/submit')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Submit incident report to owner or administrator' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Submitted incident report' })
  async submitIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.submitIncidentReport(
      parseUuidParam(id, 'incident'),
      parseZodPayload(SubmitIncidentReportSchema, body),
      auth,
    );
  }

  @Post('incidents/:id/close')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Close incident report' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Closed incident report' })
  async closeIncident(@Param('id') id: string, @Body() body: unknown, @Req() req: FastifyRequest) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.closeIncidentReport(
      parseUuidParam(id, 'incident'),
      parseZodPayload(CloseIncidentReportSchema, body),
      auth,
    );
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
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.addIncidentAction(
      parseUuidParam(id, 'incident'),
      parseZodPayload(CreateIncidentActionSchema, body),
      auth,
    );
  }

  @Patch('incidents/:id/actions/:actionId/complete')
  @RequirePermission('INCIDENT_REPORT', 'MANAGE')
  @ApiOperation({ summary: 'Complete an incident action with mandatory completion note' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Completed incident action' })
  async completeIncidentAction(
    @Param('actionId') actionId: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Param('id') incidentId?: string,
  ) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    return this.incidentsService.completeIncidentAction(
      parseActionIdParam(actionId),
      parseZodPayload(CompleteIncidentActionSchema, body),
      auth,
      incidentId ? parseUuidParam(incidentId, 'incident') : undefined,
    );
  }

  @Get('security-detection/rules')
  @RequirePermission('SECURITY_ALERT', 'VIEW')
  @ApiOperation({ summary: 'List configurable anomaly detection rules' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Detection rules list' })
  async getDetectionRules(@Req() req: FastifyRequest) {
    requireAuthenticatedPrincipal(req);
    return this.detectionService.getRules();
  }

  @Patch('security-detection/rules/:ruleCode')
  // CONFLICT-RESOLVED: Bắt buộc phạm vi toàn cục (`global = true`) cho cấu hình và kích hoạt quy tắc phát hiện xâm nhập SOC toàn hệ thống (HIGH-06).
  @RequirePermission('SECURITY_ALERT', 'MANAGE', true)
  @ApiOperation({
    summary: 'Configure anomaly detection rule parameters, threshold, window, cooldown',
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Updated detection rule' })
  async updateDetectionRule(
    @Param('ruleCode') ruleCode: string,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ) {
    const auth = requireMutatingPrincipal(this.csrf, req);
    const data = parseZodPayload(UpdateDetectionRuleConfigSchema, body);
    return this.detectionService.updateRule(ruleCode, toDetectionRulePatch(data), auth.userId);
  }

  @Post('security-detection/run')
  @RequirePermission('SECURITY_ALERT', 'MANAGE', true)
  @ApiOperation({ summary: 'Manually trigger anomaly detection run' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Detection run results' })
  async runDetection(@Body() body: unknown, @Req() req: FastifyRequest) {
    requireMutatingPrincipal(this.csrf, req);
    const data = parseZodPayload(RunDetectionInputSchema, body);
    return this.detectionService.runAllDetections(data.windowMinutes);
  }
}
