import { Injectable } from '@nestjs/common';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { AppConfigService } from '../../config/config.service.js';

@Injectable()
export class ResetMailerService {
  private readonly from: string;
  private readonly resetBaseUrl: string;
  private readonly transport: Transporter;

  constructor(config: AppConfigService) {
    this.from = config.get('SMTP_FROM');
    this.resetBaseUrl = config.get('PASSWORD_RESET_BASE_URL');
    this.transport = nodemailer.createTransport({
      host: config.get('SMTP_HOST'),
      port: config.get('SMTP_PORT'),
      secure: config.get('SMTP_SECURE'),
      connectionTimeout: 500,
      socketTimeout: 1_000,
    });
  }

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
