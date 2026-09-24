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
import { z } from 'zod';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import {
  WebAuthnAuthOptionsRequestSchema,
  WebAuthnRegistrationOptionsRequestSchema,
  WebAuthnVerifyAuthRequestSchema,
  WebAuthnVerifyRegistrationRequestSchema,
} from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { PublicEndpoint } from '../../public-endpoint.js';
import { AllowPreMfa } from './allow-pre-mfa.js';
import { AuthService, type SessionArtifacts } from './auth.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import { CsrfService } from './csrf.service.js';

const LoginSchema = z.object({
  identifier: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(128),
});
const ForgotSchema = z.object({ identifier: z.string().trim().min(1).max(255) });
const ResetSchema = z.object({
  token: z.string().min(40).max(100),
  newPassword: z.string().min(1).max(128),
});
const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
});
const EnrollmentSchema = z.object({ label: z.string().trim().min(1).max(80).optional() });
const TotpSchema = z.object({ code: z.string().regex(/^\d{6}$/) });
const MfaVerifySchema = z
  .object({
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    recoveryCode: z.string().min(16).max(64).optional(),
  })
  .refine((value) => Boolean(value.code || value.recoveryCode));
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
  ): Promise<{ authenticated: boolean; mfaRequired: boolean; enrollmentRequired: boolean }> {
    const input = this.parse(LoginSchema, body);
    const result = await this.auth.login(input.identifier, input.password, this.context(request));
    this.setSessionCookies(reply, result);
    return {
      authenticated: !result.mfaRequired,
      mfaRequired: result.mfaRequired,
      enrollmentRequired: result.enrollmentRequired,
    };
  }

  @PublicEndpoint()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ authenticated: true }> {
    this.csrf.assertRequest(request);
    const refreshToken = request.cookies?.['sda_refresh'];
    if (!refreshToken) throw new BadRequestException('Refresh request is invalid.');
    const result = await this.auth.refresh(refreshToken, this.context(request));
    this.setSessionCookies(reply, result);
    return { authenticated: true };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.auth.logout(this.principal(request), this.context(request));
    this.clearSessionCookies(reply);
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutAll(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.auth.logoutAll(this.principal(request), this.context(request));
    this.clearSessionCookies(reply);
  }

  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  async changePassword(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    const input = this.parse(ChangePasswordSchema, body);
    await this.auth.changePassword(
      this.principal(request),
      input.currentPassword,
      input.newPassword,
      this.context(request),
    );
    this.clearSessionCookies(reply);
  }

  @PublicEndpoint()
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  forgotPassword(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<{ message: string }> {
    const input = this.parse(ForgotSchema, body);
    return this.auth.forgotPassword(input.identifier, this.context(request));
  }

  @PublicEndpoint()
  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  async resetPassword(@Body() body: unknown, @Req() request: FastifyRequest): Promise<void> {
    const input = this.parse(ResetSchema, body);
    await this.auth.resetPassword(input.token, input.newPassword, this.context(request));
  }

  @AllowPreMfa()
  @Post('mfa/enroll')
  async enrollMfa(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const input = this.parse(EnrollmentSchema, body);
    return this.auth.beginMfaEnrollment(
      this.principal(request),
      input.label,
      this.context(request),
    );
  }

  @AllowPreMfa()
  @Post('mfa/enroll/verify')
  async verifyEnrollment(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ recoveryCodes: string[] }> {
    this.csrf.assertRequest(request);
    const input = this.parse(TotpSchema, body);
    const result = await this.auth.verifyMfaEnrollment(
      this.principal(request),
      input.code,
      this.context(request),
    );
    this.setSessionCookies(reply, result);
    return { recoveryCodes: result.recoveryCodes };
  }

  @AllowPreMfa()
  @Post('mfa/verify')
  async verifyMfa(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ authenticated: true }> {
    this.csrf.assertRequest(request);
    const input = this.parse(MfaVerifySchema, body);
    const result = await this.auth.verifyMfa(
      this.principal(request),
      input.code,
      input.recoveryCode,
      this.context(request),
    );
    this.setSessionCookies(reply, result);
    return { authenticated: true };
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/register/options')
  async webauthnRegisterOptions(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const input = this.parse(WebAuthnRegistrationOptionsRequestSchema, body);
    return this.auth.beginWebAuthnEnrollment(
      this.principal(request),
      input.label,
      this.context(request),
    );
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/register/verify')
  async webauthnRegisterVerify(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ recoveryCodes: string[] }> {
    this.csrf.assertRequest(request);
    const input = this.parse(WebAuthnVerifyRegistrationRequestSchema, body);
    const result = await this.auth.verifyWebAuthnEnrollment(
      this.principal(request),
      input.response as unknown as RegistrationResponseJSON,
      input.challengeToken,
      input.label,
      this.context(request),
    );
    this.setSessionCookies(reply, result);
    return { recoveryCodes: result.recoveryCodes };
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/auth/options')
  async webauthnAuthOptions(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const input = this.parse(WebAuthnAuthOptionsRequestSchema, body);
    const principal = request.auth;
    return this.auth.getWebAuthnAuthOptions(principal, input.username, this.context(request));
  }

  @AllowPreMfa()
  @Post('mfa/webauthn/auth/verify')
  async webauthnAuthVerify(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ authenticated: true }> {
    this.csrf.assertRequest(request);
    const input = this.parse(WebAuthnVerifyAuthRequestSchema, body);
    const result = await this.auth.verifyWebAuthnAuth(
      this.principal(request),
      input.response as unknown as AuthenticationResponseJSON,
      input.challengeToken,
      this.context(request),
    );
    this.setSessionCookies(reply, result);
    return { authenticated: true };
  }

  @Delete('mfa')
  @HttpCode(HttpStatus.NO_CONTENT)
  async disableMfa(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.auth.disableMfa(this.principal(request), this.context(request));
    this.clearSessionCookies(reply);
  }

  @PublicEndpoint()
  @Get('.well-known/jwks.json')
  jwks() {
    return this.auth.jwks();
  }

  private setSessionCookies(reply: FastifyReply, result: SessionArtifacts): void {
    const base = { secure: this.secureCookies, sameSite: 'strict' as const };
    reply.setCookie('sda_access', result.accessToken, {
      ...base,
      httpOnly: true,
      path: '/api/v1',
      maxAge: result.accessMaxAge,
    });
    if (result.refreshToken) {
      reply.setCookie('sda_refresh', result.refreshToken, {
        ...base,
        httpOnly: true,
        path: '/api/v1/auth',
        maxAge: result.refreshMaxAge,
      });
    } else {
      reply.clearCookie('sda_refresh', { ...base, path: '/api/v1/auth' });
    }
    reply.setCookie('sda_csrf', result.csrfToken, {
      ...base,
      httpOnly: false,
      path: '/api/v1',
      maxAge: result.refreshMaxAge,
    });
  }

  private clearSessionCookies(reply: FastifyReply): void {
    const base = { secure: this.secureCookies, sameSite: 'strict' as const };
    reply.clearCookie('sda_access', { ...base, path: '/api/v1' });
    reply.clearCookie('sda_refresh', { ...base, path: '/api/v1/auth' });
    reply.clearCookie('sda_csrf', { ...base, path: '/api/v1' });
  }

  private context(request: FastifyRequest): RequestContext {
    return {
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      correlationId: request.correlationId ?? 'unknown',
    };
  }

  private principal(request: FastifyRequest): AuthPrincipal {
    if (!request.auth) throw new BadRequestException('Authentication context is unavailable.');
    return request.auth;
  }

  private parse<T>(schema: z.ZodType<T>, body: unknown): T {
    const result = schema.safeParse(body);
    if (!result.success) throw new BadRequestException('Request validation failed.');
    return result.data;
  }
}
