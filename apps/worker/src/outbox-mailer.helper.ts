import { type getDatabaseClient } from '@sda/database';
import { randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { createTransport, type Transporter } from 'nodemailer';

/**
 * Thuật toán / Tổng quan module:
 * Bộ vận chuyển thư điện tử thực tế qua giao thức SMTP (`nodemailer`) cho hàng đợi `notification_outbox`,
 * kết hợp làm sạch ký tự điều khiển CRLF chống tấn công tiêm header SMTP, tra cứu địa chỉ người nhận an toàn,
 * cắt thời hạn cứng `5_000ms` và lưu thư dự phòng `.local/mail-sink/*.eml` (`0o600`) khi chạy `development` trên máy chủ không bật Mailpit.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface OutboxEmailMessage {
  recipient_id: bigint;
  title: string;
  body: string;
  payload: unknown;
}

const SMTP_TIMEOUT_MS = 5_000;
const LOOPBACK_SMTP_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
export const DEFAULT_WORKER_MAIL_SINK_DIR = path.resolve(
  import.meta.dirname,
  '../../../.local/mail-sink',
);

let cachedTransporterKey: string | null = null;
let cachedTransporter: Transporter | null = null;

/**
 * Thuật toán: Khử độc ký tự xuống dòng CRLF trong trường tiêu đề thư điện tử (SMTP Header Injection Sanitizer).
 * Loại bỏ toàn bộ chuỗi `\r`, `\n` và khoảng trắng thừa ở hai đầu để ngăn chặn chèn trái phép trường `Bcc:`/`Cc:`.
 */
export function sanitizeSmtpHeader(value: string): string {
  return value.replace(/[\r\n]+/gu, ' ').trim();
}

function isLoopbackDevMailSinkAllowed(smtpHost: string): boolean {
  const activeEnv = (process.env['NODE_ENV'] ?? 'development').trim().toLowerCase();
  if (activeEnv !== 'development') return false;
  if (
    process.env['NODE_TEST_CONTEXT'] &&
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] !== 'true'
  ) {
    return false;
  }
  return LOOPBACK_SMTP_HOSTS.has(smtpHost.trim().toLowerCase());
}

function isSmtpSocketFailure(err: unknown): boolean {
  const code = (err as { code?: string })?.code ?? '';
  const msg = err instanceof Error ? err.message : String(err);
  return (
    code === 'ECONNREFUSED' ||
    code === 'ESOCKET' ||
    code === 'ETIMEDOUT' ||
    /ECONNREFUSED|ETIMEDOUT|connect/iu.test(msg)
  );
}

/**
 * Thuật toán: Phân giải địa chỉ email người nhận có dự phòng CSDL (Payload-First Recipient Email Resolution).
 * Ưu tiên lấy `payload.email` đã chụp trong giao dịch gốc; nếu vắng mặt thì truy vấn bảng `users` theo `recipient_id`.
 */
export async function resolveRecipientEmail(
  database: Pick<PrismaClient, 'user'>,
  recipientId: bigint,
  payload: unknown,
): Promise<string> {
  if (payload !== null && typeof payload === 'object' && !Array.isArray(payload)) {
    const rawEmail = (payload as Record<string, unknown>)['email'];
    if (typeof rawEmail === 'string' && rawEmail.trim().length > 0) {
      return sanitizeSmtpHeader(rawEmail);
    }
  }

  if (typeof database.user?.findUnique === 'function') {
    const userRow = await database.user.findUnique({
      where: { id: recipientId },
      select: { email: true },
    });
    if (userRow?.email && userRow.email.trim().length > 0) {
      return sanitizeSmtpHeader(userRow.email);
    }
  }

  throw new Error(`Recipient email address not found for user ${recipientId.toString()}`);
}

/**
 * Thuật toán: Khởi tạo và tái sử dụng kết nối SMTP theo dấu vân tay cấu hình (Config-Keyed SMTP Transport Cache).
 */
function getSmtpTransporter(smtpHost: string): { transporter: Transporter; fromAddress: string } {
  const rawPort = Number.parseInt(process.env['SMTP_PORT']?.trim() || '1025', 10);
  const port = Number.isInteger(rawPort) && rawPort > 0 && rawPort <= 65535 ? rawPort : 1025;
  const secure = process.env['SMTP_SECURE']?.trim().toLowerCase() === 'true';
  const smtpUser = process.env['SMTP_USER']?.trim() ?? '';
  const smtpPass = process.env['SMTP_PASS'] ?? '';
  const fromAddress = sanitizeSmtpHeader(
    process.env['SMTP_FROM']?.trim() || 'no-reply@sda.internal',
  );

  const cacheKey = `${smtpHost}:${port}:${secure}:${smtpUser}`;
  if (!cachedTransporter || cachedTransporterKey !== cacheKey) {
    cachedTransporter = createTransport({
      host: smtpHost,
      port,
      secure,
      ...(smtpUser.length > 0 ? { auth: { user: smtpUser, pass: smtpPass } } : {}),
      connectionTimeout: SMTP_TIMEOUT_MS,
      greetingTimeout: SMTP_TIMEOUT_MS,
      socketTimeout: SMTP_TIMEOUT_MS,
    });
    cachedTransporterKey = cacheKey;
  }

  return { transporter: cachedTransporter, fromAddress };
}

/**
 * Thuật toán: Chuyển phát thông báo Outbox qua máy chủ SMTP thực tế có làm sạch tiêu đề;
 * khi máy chủ phát triển cục bộ không bật Mailpit ở `127.0.0.1` thì ghi tệp `.eml` (`0o600`) vào `.local/mail-sink` thay vì dồn `DEAD_LETTER`.
 */
export async function deliverOutboxEmailViaSmtp(
  database: Pick<PrismaClient, 'user'>,
  item: OutboxEmailMessage,
): Promise<void> {
  const smtpHost = process.env['SMTP_HOST']?.trim();
  if (!smtpHost) {
    throw new Error('SMTP transport is not configured (missing SMTP_HOST)');
  }

  const recipientEmail = await resolveRecipientEmail(database, item.recipient_id, item.payload);
  const { transporter, fromAddress } = getSmtpTransporter(smtpHost);
  const cleanSubject = sanitizeSmtpHeader(item.title);

  try {
    await transporter.sendMail({
      from: fromAddress,
      to: recipientEmail,
      subject: cleanSubject,
      text: item.body,
    });
  } catch (err: unknown) {
    if (!isLoopbackDevMailSinkAllowed(smtpHost) || !isSmtpSocketFailure(err)) {
      throw err;
    }
    const sinkDir = path.resolve(
      process.env['SDA_DEV_MAIL_SINK_DIR']?.trim() || DEFAULT_WORKER_MAIL_SINK_DIR,
    );
    await fsp.mkdir(sinkDir, { recursive: true, mode: 0o700 });
    const emlPath = path.join(sinkDir, `${Date.now()}-outbox-${randomUUID()}.eml`);
    const emlContent = [
      `Date: ${new Date().toUTCString()}`,
      `From: ${fromAddress}`,
      `To: ${recipientEmail}`,
      `Subject: ${cleanSubject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      item.body,
      '',
    ].join('\r\n');
    await fsp.writeFile(emlPath, emlContent, { encoding: 'utf8', mode: 0o600 });
  }
}
