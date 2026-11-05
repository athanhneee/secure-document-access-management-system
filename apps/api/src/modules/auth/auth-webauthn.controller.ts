/**
 * @module AuthWebAuthnController
 * Algorithm: FIDO2 / WebAuthn Step-Up MFA Registration & Assertion HTTP Controller.
 */
import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { AllowPreMfa } from './allow-pre-mfa.js';
import { AuthService } from './auth.service.js';
import { CsrfService } from './csrf.service.js';
import * as S from './auth.schemas.js';
import {
  extractAuthRequestContext,
  guardAuthenticatedBody,
  setAuthSessionCookies,
} from './auth-cookies.helper.js';

@ApiTags('auth')
@Controller('auth')
export class AuthWebAuthnController {
  private readonly secureCookies: boolean;

  constructor(
    private readonly auth: AuthService,
    private readonly csrf: CsrfService,
    config: AppConfigService,
  ) {
    this.secureCookies = config.isProduction;
  }

  /**
   * Thuật toán: Cấp phát tham số thử thách đăng ký khóa phần cứng FIDO2/WebAuthn có kiểm tra CSRF.
   */
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

  /**
   * Thuật toán: Xác minh phản hồi đăng ký khóa công khai WebAuthn, kích hoạt phiên MFA và sinh mã khôi phục.
   */
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

  /**
   * Thuật toán: Sinh thử thách xác thực chữ ký WebAuthn cho các khóa đã kích hoạt của tài khoản.
   */
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

  /**
   * Thuật toán: Xác minh chữ ký phần cứng WebAuthn, kiểm tra bộ đếm nhân bản và thăng cấp phiên MFA.
   */
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
}
