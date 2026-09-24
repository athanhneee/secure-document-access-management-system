import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { AuthAuditService } from './auth-audit.service.js';
import { AuthRepository } from './auth.repository.js';
import { CsrfService } from './csrf.service.js';
import { LoginRateLimitService } from './login-rate-limit.service.js';
import { MfaService } from './mfa.service.js';
import { PasswordService } from './password.service.js';
import { ResetMailerService } from './reset-mailer.service.js';
import { TokenService } from './token.service.js';
import { WebAuthnService } from './webauthn.service.js';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthAuditService,
    AuthRepository,
    CsrfService,
    LoginRateLimitService,
    MfaService,
    PasswordService,
    ResetMailerService,
    TokenService,
    WebAuthnService,
  ],
  exports: [
    AuthService,
    AuthRepository,
    TokenService,
    CsrfService,
    PasswordService,
    WebAuthnService,
  ],
})
export class AuthModule {}
