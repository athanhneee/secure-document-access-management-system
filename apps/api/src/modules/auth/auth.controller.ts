/**
 * @module AuthController
 * Algorithm: Cookie-Bound Authentication, Session Management, TOTP/WebAuthn Step-Up MFA & CSRF-Protected HTTP Controller.
 */
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';
import { PublicEndpoint } from '../../public-endpoint.js';
import { AllowAuthenticatedSelf } from '../rbac/require-permission.js';
import { AllowPreMfa } from './allow-pre-mfa.js';
import { AuthService } from './auth.service.js';
import { CsrfService } from './csrf.service.js';
import * as S from './auth.schemas.js';
import {
  clearAuthSessionCookies,
  extractAuthRequestContext,
  guardAuthenticatedBody,
  requireAuthPrincipal,
  setAuthSessionCookies,
} from './auth-cookies.helper.js';

@ApiTags('auth')
@AllowAuthenticatedSelf()
@Controller('auth')
export class AuthController {
  private readonly secureCookies: boolean;

  constructor(
    private readonly auth: AuthService,
    private readonly csrf: CsrfService,
    config: AppConfigService,
  ) {
    this.secureCookies = config.isProduction;
  }

  @PublicEndpoint()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Authenticate credentials without exposing token material to JavaScript',
  })
  @ApiResponse({ status: HttpStatus.OK })
  async login(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const input = S.parseAuthBody(S.LoginSchema, body);
    const res = await this.auth.login(
      input.identifier,
      input.password,
      extractAuthRequestContext(request),
    );
    setAuthSessionCookies(reply, res, this.secureCookies);
    return {
      authenticated: !res.mfaRequired,
      mfaRequired: res.mfaRequired,
      enrollmentRequired: res.enrollmentRequired,
    };
  }

  @PublicEndpoint()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() request: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    this.csrf.assertRequest(request);
    const refreshToken = request.cookies?.['sda_refresh'];
    if (!refreshToken) throw new BadRequestException('Refresh request is invalid.');
    const result = await this.auth.refresh(refreshToken, extractAuthRequestContext(request));
    setAuthSessionCookies(reply, result, this.secureCookies);
    return { authenticated: true as const };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() request: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    this.csrf.assertRequest(request);
    await this.auth.logout(requireAuthPrincipal(request), extractAuthRequestContext(request));
    clearAuthSessionCookies(reply, this.secureCookies);
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutAll(@Req() request: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    this.csrf.assertRequest(request);
    await this.auth.logoutAll(requireAuthPrincipal(request), extractAuthRequestContext(request));
    clearAuthSessionCookies(reply, this.secureCookies);
  }

  // CONFLICT-RESOLVED: Bổ sung quản lý phiên thiết bị (sessions, logout-others, DELETE sessions/:sessionId) giữ nguyên logout-all (HIGH-10)
  @Get('sessions')
  listSessions(@Req() request: FastifyRequest) {
    return this.auth.listSessions(requireAuthPrincipal(request));
  }

  @Post('logout-others')
  @HttpCode(HttpStatus.OK)
  logoutOthers(@Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.auth.logoutOthers(
      requireAuthPrincipal(request),
      extractAuthRequestContext(request),
    );
  }

  @Delete('sessions/:sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSession(
    @Param('sessionId') sessionId: string,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    const result = await this.auth.revokeTargetSession(
      requireAuthPrincipal(request),
      sessionId,
      extractAuthRequestContext(request),
    );
    if (result.clearedCurrentCookies) {
      clearAuthSessionCookies(reply, this.secureCookies);
    }
  }

  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  async changePassword(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.ChangePasswordSchema,
      body,
    );
    await this.auth.changePassword(principal, input.currentPassword, input.newPassword, context);
    clearAuthSessionCookies(reply, this.secureCookies);
  }

  @PublicEndpoint()
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  forgotPassword(@Body() body: unknown, @Req() request: FastifyRequest) {
    const input = S.parseAuthBody(S.ForgotSchema, body);
    return this.auth.forgotPassword(input.identifier, extractAuthRequestContext(request));
  }

  @PublicEndpoint()
  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  async resetPassword(@Body() body: unknown, @Req() request: FastifyRequest): Promise<void> {
    const input = S.parseAuthBody(S.ResetSchema, body);
    await this.auth.resetPassword(
      input.token,
      input.newPassword,
      extractAuthRequestContext(request),
    );
  }

  @AllowPreMfa()
  @Post('mfa/enroll')
  async enrollMfa(@Body() body: unknown, @Req() req: FastifyRequest) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.EnrollmentSchema,
      body,
    );
    return this.auth.beginMfaEnrollment(principal, input.label, context);
  }

  @AllowPreMfa()
  @Post('mfa/enroll/verify')
  async verifyEnrollment(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.TotpSchema,
      body,
    );
    const result = await this.auth.verifyMfaEnrollment(principal, input.code, context);
    setAuthSessionCookies(reply, result, this.secureCookies);
    return { recoveryCodes: result.recoveryCodes };
  }

  @AllowPreMfa()
  @Post('mfa/verify')
  async verifyMfa(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.MfaVerifySchema,
      body,
    );
    const result = await this.auth.verifyMfa(principal, input.code, input.recoveryCode, context);
    setAuthSessionCookies(reply, result, this.secureCookies);
    return { authenticated: true as const };
  }

  @Delete('mfa')
  @HttpCode(HttpStatus.NO_CONTENT)
  async disableMfa(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.DisableMfaSchema,
      body,
    );
    await this.auth.disableMfa(
      principal,
      input.currentPassword,
      input.code,
      input.recoveryCode,
      context,
    );
    clearAuthSessionCookies(reply, this.secureCookies);
  }

  @PublicEndpoint()
  @Get('.well-known/jwks.json')
  jwks() {
    return this.auth.jwks();
  }
}
