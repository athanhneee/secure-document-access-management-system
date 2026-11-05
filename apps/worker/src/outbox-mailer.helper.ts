import { type getDatabaseClient } from '@sda/database';
import { createTransport, type Transporter } from 'nodemailer';

/**
 * Thuật toán / Tổng quan module:
 * Bộ vận chuyển thư điện tử thực tế qua giao thức SMTP (`nodemailer`) cho hàng đợi `notification_outbox`,
 * kết hợp làm sạch ký tự điều khiển CRLF chống tấn công tiêm header SMTP và tra cứu địa chỉ người nhận an toàn.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface OutboxEmailMessage {
  recipient_id: bigint;
  title: string;
  body: string;
  payload: unknown;
}

let cachedTransporterKey: string | null = null;
let cachedTransporter: Transporter | null = null;

/**
 * Thuật toán: Khử độc ký tự xuống dòng CRLF trong trường tiêu đề thư điện tử (SMTP Header Injection Sanitizer).
 * Loại bỏ toàn bộ chuỗi `\r`, `\n` và khoảng trắng thừa ở hai đầu để ngăn chặn chèn trái phép trường `Bcc:`/`Cc:`.
 */
export function sanitizeSmtpHeader(value: string): string {
  return value.replace(/[\r\n]+/gu, ' ').trim();
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
    });
    cachedTransporterKey = cacheKey;
  }

  return { transporter: cachedTransporter, fromAddress };
}

/**
 * Thuật toán: Chuyển phát thông báo Outbox qua máy chủ SMTP thực tế có làm sạch tiêu đề (Sanitized SMTP Outbox Delivery).
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

  await transporter.sendMail({
    from: fromAddress,
    to: recipientEmail,
    subject: sanitizeSmtpHeader(item.title),
    text: item.body,
  });
}
