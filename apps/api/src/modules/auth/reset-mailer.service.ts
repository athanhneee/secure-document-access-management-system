/**
 * @module ResetMailerService
 * Thuật toán: Gửi thư khôi phục mật khẩu qua giao thức SMTP có hỗ trợ xác thực `SMTP_USER` / `SMTP_PASS`,
 * kênh mã hóa TLS (`SMTP_SECURE`), ngưỡng cắt kết nối `5_000ms` và hố thu thư phát triển cục bộ (`.local/mail-sink/*.eml`, `0o600`)
 * khi chạy trực tiếp trên Windows/Linux không bật container Mailpit ở địa chỉ loopback (`127.0.0.1` / `localhost` / `::1`).
 */
import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { AppConfigService } from '../../config/config.service.js';

const SMTP_TIMEOUT_MS = 5_000;
const LOOPBACK_SMTP_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const DEFAULT_DEV_MAIL_SINK_DIR = path.resolve(
  import.meta.dirname,
  '../../../../../.local/mail-sink',
);

function isLoopbackDevFallbackAllowed(host: string, configuredEnv: string): boolean {
  const activeEnv = (process.env['NODE_ENV'] ?? configuredEnv).trim().toLowerCase();
  if (activeEnv !== 'development') return false;
  if (
    process.env['NODE_TEST_CONTEXT'] &&
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] !== 'true'
  ) {
    return false;
  }
  return LOOPBACK_SMTP_HOSTS.has(host.trim().toLowerCase());
}

function isSmtpConnectionError(err: unknown): boolean {
  const code = (err as { code?: string })?.code ?? '';
  const msg = err instanceof Error ? err.message : String(err);
  return (
    code === 'ECONNREFUSED' ||
    code === 'ESOCKET' ||
    code === 'ETIMEDOUT' ||
    /ECONNREFUSED|ETIMEDOUT|connect/iu.test(msg)
  );
}

@Injectable()
export class ResetMailerService {
  private readonly logger = new Logger(ResetMailerService.name);
  private readonly host: string;
  private readonly from: string;
  private readonly resetBaseUrl: string;
  private readonly configuredEnv: string;
  private readonly transport: Transporter;

  /**
   * Thuật toán: Khởi tạo kết nối SMTP có xác thực tùy chọn khi cấu hình đầy đủ `SMTP_USER` và `SMTP_PASS`.
   */
  constructor(config: AppConfigService) {
    this.host = config.get('SMTP_HOST');
    this.from = config.get('SMTP_FROM');
    this.resetBaseUrl = config.get('PASSWORD_RESET_BASE_URL');
    this.configuredEnv = String(config.get('NODE_ENV') ?? 'development');
    const smtpUser = config.get('SMTP_USER');
    const smtpPass = config.get('SMTP_PASS');
    this.transport = nodemailer.createTransport({
      host: this.host,
      port: config.get('SMTP_PORT'),
      secure: config.get('SMTP_SECURE'),
      ...(smtpUser && smtpPass ? { auth: { user: smtpUser, pass: smtpPass } } : {}),
      connectionTimeout: SMTP_TIMEOUT_MS,
      greetingTimeout: SMTP_TIMEOUT_MS,
      socketTimeout: SMTP_TIMEOUT_MS,
    });
  }

  /**
   * Thuật toán: Đóng gói liên kết đặt lại mật khẩu dùng một lần vào tham số truy vấn URL chuẩn hóa và phát thư SMTP;
   * nếu chạy `development` không bật Mailpit cục bộ thì lưu tệp RFC-5322 `.eml` phân quyền `0o600` (không ghi token ra log).
   */
  async send(to: string, token: string): Promise<void> {
    const link = new URL(this.resetBaseUrl);
    link.searchParams.set('token', token);
    const subject = '[SecureDocument] Yêu cầu đặt lại mật khẩu';
    const text = [
      'Bạn đã gửi yêu cầu đặt lại mật khẩu tài khoản SecureDocument.',
      'Vui lòng mở liên kết dùng một lần dưới đây trong thời hạn hiệu lực để thiết lập mật khẩu mới:',
      '',
      link.toString(),
      '',
      'Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này.',
    ].join('\n');

    try {
      await this.transport.sendMail({
        from: this.from,
        to,
        subject,
        text,
      });
    } catch (err: unknown) {
      if (
        !isLoopbackDevFallbackAllowed(this.host, this.configuredEnv) ||
        !isSmtpConnectionError(err)
      ) {
        throw err;
      }
      const sinkDir = path.resolve(
        process.env['SDA_DEV_MAIL_SINK_DIR']?.trim() || DEFAULT_DEV_MAIL_SINK_DIR,
      );
      await fsp.mkdir(sinkDir, { recursive: true, mode: 0o700 });
      const emlPath = path.join(sinkDir, `${Date.now()}-reset-${randomUUID()}.eml`);
      const emlBody = [
        `Date: ${new Date().toUTCString()}`,
        `From: ${this.from.replace(/[\r\n]+/gu, ' ').trim()}`,
        `To: ${to.replace(/[\r\n]+/gu, ' ').trim()}`,
        `Subject: ${subject}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        '',
        text,
        '',
      ].join('\r\n');
      await fsp.writeFile(emlPath, emlBody, { encoding: 'utf8', mode: 0o600 });
      this.logger.warn(
        `Loopback SMTP offline in development; spooled reset email to ${path.basename(emlPath)}`,
      );
    }
  }
}
