/**
 * @module CsrfService
 * Dịch vụ chống giả mạo yêu cầu liên trang (Cross-Site Request Forgery) kết hợp kiểm tra Origin
 * nghiêm ngặt và mẫu Double-Submit Cookie so sánh thời gian hằng số.
 */
import { timingSafeEqual } from 'node:crypto';
import { ForbiddenException, Injectable } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';

@Injectable()
export class CsrfService {
  private readonly allowedOrigins: Set<string>;

  constructor(config: AppConfigService) {
    this.allowedOrigins = new Set(config.corsOrigins);
  }

  /**
   * Thuật toán: Xác thực kép Origin Whitelist + Double-Submit Cookie bằng `timingSafeEqual`.
   * Cơ chế hoạt động:
   *   1. Kiểm tra `Origin` header thuộc danh sách trắng O(1) qua cấu trúc `Set`.
   *   2. Đọc giá trị cookie `sda_csrf` và header `x-csrf-token`, đảm bảo độ dài tối thiểu 32 ký tự,
   *      hai chuỗi bằng độ dài nhau và khớp từng byte trong thời gian hằng số để chống tấn công kênh kề thời gian.
   */
  assertRequest(request: FastifyRequest): void {
    const origin = request.headers.origin;
    if (typeof origin !== 'string' || !this.allowedOrigins.has(origin)) {
      throw new ForbiddenException('Request origin is not allowed.');
    }
    const cookieToken = request.cookies?.['sda_csrf'];
    const headerToken = request.headers['x-csrf-token'];
    if (typeof cookieToken !== 'string' || typeof headerToken !== 'string') {
      throw new ForbiddenException('CSRF validation failed.');
    }
    const cookieBuffer = Buffer.from(cookieToken, 'utf8');
    const headerBuffer = Buffer.from(headerToken, 'utf8');
    if (
      cookieToken.length < 32 ||
      cookieBuffer.byteLength !== headerBuffer.byteLength ||
      !timingSafeEqual(cookieBuffer, headerBuffer)
    ) {
      throw new ForbiddenException('CSRF validation failed.');
    }
  }
}
