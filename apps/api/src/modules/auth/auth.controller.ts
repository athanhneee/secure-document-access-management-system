/**
 * @module AuthController
 * Algorithm: Cookie-Bound Authentication, TOTP/WebAuthn Step-Up MFA & CSRF-Protected HTTP Controller.
 */
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { PublicEndpoint } from '../../public-endpoint.js';
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
  async logout(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.auth.logout(requireAuthPrincipal(request), extractAuthRequestContext(request));
    clearAuthSessionCookies(reply, this.secureCookies);
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutAll(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.auth.logoutAll(requireAuthPrincipal(request), extractAuthRequestContext(request));
    clearAuthSessionCookies(reply, this.secureCookies);
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

  @AllowPreMfa()
  @Post('mfa/webauthn/register/options')
  async webauthnRegisterOptions(@Body() body: unknown, @Req() req: FastifyRequest) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.WebAuthnRegistrationOptionsRequestSchema,
      body,
    );
    return this.auth.beginWebAuthnEnrollment(principal, input.label, context);
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/register/verify')
  async webauthnRegisterVerify(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.WebAuthnVerifyRegistrationRequestSchema,
      body,
    );
    const result = await this.auth.verifyWebAuthnEnrollment(
      principal,
      input.response as unknown as RegistrationResponseJSON,
      input.challengeToken,
      input.label,
      context,
    );
    setAuthSessionCookies(reply, result, this.secureCookies);
    return { recoveryCodes: result.recoveryCodes };
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/auth/options')
  async webauthnAuthOptions(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const input = S.parseAuthBody(S.WebAuthnAuthOptionsRequestSchema, body);
    return this.auth.getWebAuthnAuthOptions(
      request.auth,
      input.username,
      extractAuthRequestContext(request),
    );
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/auth/verify')
  async webauthnAuthVerify(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { input, principal, context } = guardAuthenticatedBody(
      this.csrf,
      req,
      S.WebAuthnVerifyAuthRequestSchema,
      body,
    );
    const result = await this.auth.verifyWebAuthnAuth(
      principal,
      input.response as unknown as AuthenticationResponseJSON,
      input.challengeToken,
      context,
    );
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
