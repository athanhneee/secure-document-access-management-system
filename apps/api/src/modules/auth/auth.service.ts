/**
 * @module AuthService
 * Thuật toán: Điều phối trung tâm xác thực đa giai đoạn hằng thời gian (Constant-Work Login chống dò tài khoản),
 * xoay vòng Refresh Token theo chuẩn RFC 9700 kèm phát hiện tái sử dụng cây họ token, quản lý vòng đời phiên
 * thiết bị và xác thực đa nhân tố TOTP / WebAuthn FIDO2.
 */
import { Injectable, Optional } from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { AuthAuditService } from './auth-audit.service.js';
import {
  executeBeginMfaEnrollment,
  executeDisableMfa,
  executeVerifyMfa,
  executeVerifyMfaEnrollment,
} from './auth-mfa.helper.js';
import {
  executeChangePassword,
  executeForgotPassword,
  executeResetPassword,
} from './auth-password.helper.js';
import { executeLogin, executeRefresh } from './auth-session.helper.js';
import {
  executeRevokeTargetSession,
  type ActiveAuthSessionItem,
} from './auth-sessions-management.helper.js';
import {
  executeBeginWebAuthnEnrollment,
  executeGetWebAuthnAuthOptions,
  executeVerifyWebAuthnAuth,
  executeVerifyWebAuthnEnrollment,
} from './auth-webauthn.helper.js';
import { AuthRepository } from './auth.repository.js';
import type { AuthPrincipal, AuthUserProfile, RequestContext } from './auth.types.js';
import { LoginRateLimitService } from './login-rate-limit.service.js';
import { MfaService } from './mfa.service.js';
import { PasswordService } from './password.service.js';
import { ResetMailerService } from './reset-mailer.service.js';
import { TokenService } from './token.service.js';
import { WebAuthnService } from './webauthn.service.js';

export interface SessionArtifacts {
  accessToken: string;
  refreshToken?: string | undefined;
  csrfToken: string;
  accessMaxAge: number;
  refreshMaxAge: number;
  mfaRequired: boolean;
  enrollmentRequired: boolean;
  user?: AuthUserProfile | undefined;
}

@Injectable()
export class AuthService {
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly resetTtl: number;
  private readonly webauthn: WebAuthnService;

  constructor(
    private readonly repository: AuthRepository,
    private readonly passwords: PasswordService,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly rateLimit: LoginRateLimitService,
    private readonly audit: AuthAuditService,
    private readonly mailer: ResetMailerService,
    config: AppConfigService,
    @Optional() webauthn?: WebAuthnService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.webauthn = webauthn ?? new WebAuthnService(this.mfa, config, stateStore);
    this.accessTtl = config.get('AUTH_ACCESS_TTL_SECONDS');
    this.refreshTtl = config.get('AUTH_REFRESH_TTL_SECONDS');
    this.resetTtl = config.get('AUTH_RESET_TTL_SECONDS');
  }

  /** Thuật toán: Xác thực thông tin đăng nhập hằng thời gian kèm giới hạn tốc độ và khởi tạo phiên. */
  login(identifier: string, password: string, context: RequestContext): Promise<SessionArtifacts> {
    return executeLogin(this.deps(), identifier, password, context);
  }

  /** Thuật toán: Xoay vòng Refresh Token một lần dùng và thu hồi toàn bộ cây họ token nếu phát hiện dùng lại. */
  refresh(refreshToken: string, context: RequestContext): Promise<SessionArtifacts> {
    return executeRefresh(this.deps(), refreshToken, context);
  }

  /** Thuật toán: Thu hồi phiên hiện tại và ghi nhật ký kiểm toán `LOGOUT`. */
  async logout(principal: AuthPrincipal, context: RequestContext): Promise<void> {
    await this.repository.revokeSession(principal.sessionId, principal.userId, 'USER_LOGOUT');
    await this.audit.record(
      {
        action: 'LOGOUT',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: principal.sessionId,
      },
      context,
    );
  }

  /** Thuật toán: Thu hồi toàn bộ phiên đang hoạt động trên mọi thiết bị của người dùng (`LOGOUT_ALL`). */
  async logoutAll(principal: AuthPrincipal, context: RequestContext): Promise<void> {
    const count = await this.repository.revokeAllSessions(principal.userId, 'USER_LOGOUT_ALL');
    await this.audit.record(
      {
        action: 'LOGOUT_ALL',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: { revokedSessions: count },
      },
      context,
    );
  }

  /** Thuật toán: Truy xuất danh sách phiên thiết bị đang hoạt động kèm trạng thái xác thực `mfaVerified`. */
  async listSessions(principal: AuthPrincipal): Promise<{ data: ActiveAuthSessionItem[] }> {
    const data = await this.repository.listActiveSessions(principal.userId, principal.sessionId);
    return { data };
  }

  /** Thuật toán: Thu hồi mọi phiên song song khác của người dùng mà vẫn bảo toàn phiên hiện hành (`LOGOUT_OTHERS`). */
  async logoutOthers(
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ revokedCount: number }> {
    const revokedCount = await this.repository.revokeOtherSessions(
      principal.userId,
      principal.sessionId,
      'USER_LOGOUT_OTHERS',
    );
    await this.audit.record(
      {
        action: 'LOGOUT_OTHERS',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: { revokedSessions: revokedCount },
      },
      context,
    );
    return { revokedCount };
  }

  /** Thuật toán: Thu hồi đích danh một phiên theo `sessionId` và báo hiệu xóa cookie nếu trùng phiên hiện tại. */
  revokeTargetSession(
    principal: AuthPrincipal,
    targetSessionId: string,
    context: RequestContext,
  ): Promise<{ clearedCurrentCookies: boolean }> {
    return executeRevokeTargetSession({
      repository: this.repository,
      audit: this.audit,
      principal,
      targetSessionId,
      context,
    });
  }

  /** Thuật toán: Xác minh mật khẩu cũ, băm Argon2id mật khẩu mới và thu hồi các phiên thiết bị cũ. */
  changePassword(
    principal: AuthPrincipal,
    currentPassword: string,
    newPassword: string,
    context: RequestContext,
  ): Promise<void> {
    return executeChangePassword(this.deps(), principal, currentPassword, newPassword, context);
  }

  /** Thuật toán: Phát hành mã đặt lại mật khẩu một lần dùng chống dò tìm tài khoản (Enumeration-Safe). */
  forgotPassword(identifier: string, context: RequestContext): Promise<{ message: string }> {
    return executeForgotPassword(this.deps(), identifier, context);
  }

  /** Thuật toán: Tiêu thụ nguyên tử mã đặt lại mật khẩu, cập nhật Argon2id và thu hồi mọi phiên cũ. */
  resetPassword(token: string, newPassword: string, context: RequestContext): Promise<void> {
    return executeResetPassword(this.deps(), token, newPassword, context);
  }

  /** Thuật toán: Khởi tạo khóa bí mật TOTP mã hóa và sinh mã QR đăng ký xác thực hai lớp. */
  beginMfaEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ): Promise<{ secret: string; uri: string; qrCodeDataUrl: string }> {
    return executeBeginMfaEnrollment(this.deps(), principal, label, context);
  }

  /** Thuật toán: Xác nhận mã TOTP lần đầu, kích hoạt yếu tố MFA, sinh mã khôi phục và nâng cấp phiên. */
  verifyMfaEnrollment(
    principal: AuthPrincipal,
    code: string,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    return executeVerifyMfaEnrollment(this.deps(), principal, code, context);
  }

  /** Thuật toán: Sinh thử thách mật mã học WebAuthn FIDO2 để đăng ký khóa bảo mật phần cứng / Passkey. */
  beginWebAuthnEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ) {
    return executeBeginWebAuthnEnrollment(this.deps(), principal, label, context);
  }

  /** Thuật toán: Kiểm chứng chữ ký khóa công khai WebAuthn khi đăng ký và nâng cấp phiên đã xác thực MFA. */
  verifyWebAuthnEnrollment(
    principal: AuthPrincipal,
    response: RegistrationResponseJSON,
    challengeToken: string,
    label: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    return executeVerifyWebAuthnEnrollment(
      this.deps(),
      principal,
      response,
      challengeToken,
      label,
      context,
    );
  }

  /** Thuật toán: Phát hành thử thách xác thực WebAuthn gắn với khóa đã đăng ký của người dùng. */
  getWebAuthnAuthOptions(
    principal: AuthPrincipal | undefined,
    username: string | undefined,
    context: RequestContext,
  ) {
    return executeGetWebAuthnAuthOptions(this.deps(), principal, username, context);
  }

  /** Thuật toán: Kiểm chứng phản hồi chữ ký WebAuthn kèm bộ đếm chống nhân bản khóa (`signCount`). */
  verifyWebAuthnAuth(
    principal: AuthPrincipal,
    response: AuthenticationResponseJSON,
    challengeToken: string,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    return executeVerifyWebAuthnAuth(this.deps(), principal, response, challengeToken, context);
  }

  /** Thuật toán: Xác thực bước hai bằng mã TOTP chống phát lại hoặc tiêu thụ mã khôi phục dự phòng. */
  verifyMfa(
    principal: AuthPrincipal,
    code: string | undefined,
    recoveryCode: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    return executeVerifyMfa(this.deps(), principal, code, recoveryCode, context);
  }

  /** Thuật toán: Hủy kích hoạt MFA có kiểm tra mật khẩu + mã xác thực và chặn gỡ MFA đối với vai trò bắt buộc. */
  disableMfa(
    principal: AuthPrincipal,
    currentPassword: string,
    code: string | undefined,
    recoveryCode: string | undefined,
    context: RequestContext,
  ): Promise<void> {
    return executeDisableMfa(this.deps(), principal, currentPassword, code, recoveryCode, context);
  }

  /** Thuật toán: Công bố tập khóa công khai JSON Web Key Set (JWKS) phục vụ xác minh chữ ký JWT bất đối xứng. */
  jwks(): ReturnType<TokenService['jwks']> {
    return this.tokens.jwks();
  }

  /** Thuật toán: Đóng gói túi phụ thuộc nội bộ truyền xuống các hàm thực thi chuyên biệt theo miền. */
  private deps() {
    return {
      repository: this.repository,
      passwords: this.passwords,
      tokens: this.tokens,
      mfa: this.mfa,
      rateLimit: this.rateLimit,
      audit: this.audit,
      mailer: this.mailer,
      webauthn: this.webauthn,
      accessTtl: this.accessTtl,
      refreshTtl: this.refreshTtl,
      resetTtl: this.resetTtl,
    };
  }
}
