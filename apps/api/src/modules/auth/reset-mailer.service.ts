/**
 * @module ResetMailerService
 * Thuật toán: Gửi thư khôi phục mật khẩu qua giao thức SMTP có hỗ trợ xác thực `SMTP_USER` / `SMTP_PASS`,
 * kênh mã hóa TLS (`SMTP_SECURE`) và ngưỡng cắt kết nối/phản hồi an toàn `5_000ms` chống treo phiên chuyển tiếp thư.
 */
import { Injectable } from '@nestjs/common';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { AppConfigService } from '../../config/config.service.js';

const SMTP_TIMEOUT_MS = 5_000;

@Injectable()
export class ResetMailerService {
  private readonly from: string;
  private readonly resetBaseUrl: string;
  private readonly transport: Transporter;

  /**
   * Thuật toán: Khởi tạo kết nối SMTP có xác thực tùy chọn khi cấu hình đầy đủ `SMTP_USER` và `SMTP_PASS`.
   */
  constructor(config: AppConfigService) {
    this.from = config.get('SMTP_FROM');
    this.resetBaseUrl = config.get('PASSWORD_RESET_BASE_URL');
    const smtpUser = config.get('SMTP_USER');
    const smtpPass = config.get('SMTP_PASS');
    this.transport = nodemailer.createTransport({
      host: config.get('SMTP_HOST'),
      port: config.get('SMTP_PORT'),
      secure: config.get('SMTP_SECURE'),
      ...(smtpUser && smtpPass ? { auth: { user: smtpUser, pass: smtpPass } } : {}),
      connectionTimeout: SMTP_TIMEOUT_MS,
      greetingTimeout: SMTP_TIMEOUT_MS,
      socketTimeout: SMTP_TIMEOUT_MS,
    });
  }

  /**
   * Thuật toán: Đóng gói liên kết đặt lại mật khẩu dùng một lần vào tham số truy vấn URL chuẩn hóa và phát thư SMTP.
   */
  async send(to: string, token: string): Promise<void> {
    const link = new URL(this.resetBaseUrl);
    link.searchParams.set('token', token);
    await this.transport.sendMail({
      from: this.from,
      to,
      subject: 'Password reset request',
      text: `Use this one-time link within the configured expiry window: ${link.toString()}`,
    });
  }
}
