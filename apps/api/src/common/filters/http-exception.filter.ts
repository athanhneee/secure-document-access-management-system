/**
 * Module: Bộ lọc Ngoại lệ HTTP Toàn cục (Global Fail-Safe HTTP Exception Filter)
 * Thuật toán: Chuẩn hóa phản hồi lỗi đa hình sang cấu trúc `ErrorEnvelope` thống nhất
 *   kết hợp ngăn chặn rò rỉ chi tiết nội bộ (Stack Trace / SQL Error Masking).
 */
import {
  type ArgumentsHost,
  type ExceptionFilter,
  Catch,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { ZodError } from 'zod';
import { AppErrorCode, type ErrorEnvelope } from '@sda/contracts';
import {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseError,
  DatabaseNotFoundError,
  DatabaseUnavailableError,
  isDatabaseOperationError,
  mapDatabaseError,
} from '@sda/database';
import { JsonLoggerService } from '../logger/json-logger.service.js';

const SAFE_CORRELATION_ID_RE = /^[a-zA-Z0-9._:-]{1,128}$/;

/**
 * Thuật toán: Trích xuất mã lỗi Prisma/SQLSTATE lồng nhau để phân biệt vi phạm khóa duy nhất (`P2002`/`23505`) với lỗi ràng buộc dữ liệu khác.
 */
function extractRawDbErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const rec = error as Record<string, unknown>;
  if (typeof rec['code'] === 'string') return rec['code'];
  if (typeof rec['sqlState'] === 'string') return rec['sqlState'];
  return undefined;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new JsonLoggerService(HttpExceptionFilter.name);

  /**
   * Thuật toán: Phân loại Ngoại lệ Đa hình & Ánh xạ Mã lỗi Chuẩn hóa (Polymorphic Exception Mapping)
   * Mục đích: Biến đổi mọi ngoại lệ phát sinh trong pipeline thành cấu trúc JSON `ErrorEnvelope`
   *   nhất quán mà không làm lộ stack trace hoặc chi tiết hệ thống nội bộ cho phía client.
   * Cơ chế hoạt động:
   *   - Giải quyết `correlationId` an toàn: Ưu tiên giá trị đã gắn trên request; nếu đọc từ header
   *     thì kiểm tra khớp biểu thức chính quy whitelist `SAFE_CORRELATION_ID_RE` để chống HTTP Response
   *     Splitting / Log Injection, ngược lại sinh mới UUIDv4 ngẫu nhiên.
   *   - Phân nhánh xử lý theo kiểu ngoại lệ:
   *     1. `HttpException`: Trích xuất `statusCode`, `errorCode`, `message`, `details`; nếu chưa có
   *        `errorCode` riêng thì ánh xạ tất định từ HTTP status sang `AppErrorCode`.
   *     2. `ZodError`: Chuyển thành lỗi 400 `VALIDATION_FAILED` kèm danh sách đường dẫn trường lỗi phẳng hóa.
   *     3. Lỗi không xác định khác: Ghi log mức `error` nội bộ kèm `stack` và `correlationId`, nhưng chỉ
   *        trả thông báo 500 tổng quát cho client.
   *   - Đính kèm header truy vết và `cache-control: no-store` để ngăn bộ nhớ đệm lưu trữ phản hồi lỗi.
   */
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const reply = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const rawHeaderCorrId =
      typeof request.headers['x-correlation-id'] === 'string'
        ? request.headers['x-correlation-id'].trim()
        : undefined;
    const correlationId =
      request.correlationId ??
      (rawHeaderCorrId && SAFE_CORRELATION_ID_RE.test(rawHeaderCorrId)
        ? rawHeaderCorrId
        : randomUUID());

    let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    let errorCode: string = AppErrorCode.INTERNAL_SERVER_ERROR;
    let message =
      'An unexpected internal error occurred. Contact the administrator with the correlation ID.';
    let details: unknown = undefined;

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const response = exception.getResponse();

      if (typeof response === 'string') {
        message = response;
      } else if (typeof response === 'object' && response !== null) {
        const resObj = response as Record<string, unknown>;
        if (typeof resObj['errorCode'] === 'string') {
          errorCode = resObj['errorCode'];
        }
        if (typeof resObj['message'] === 'string') {
          message = resObj['message'];
        } else if (Array.isArray(resObj['message'])) {
          message = 'Validation failed for one or more fields.';
          details = resObj['message'];
        }
        if (resObj['details'] !== undefined) {
          details = resObj['details'];
        }
      }

      // Default errorCode based on standard HTTP status codes if not explicitly set
      if (errorCode === AppErrorCode.INTERNAL_SERVER_ERROR) {
        switch (statusCode) {
          case HttpStatus.BAD_REQUEST:
            errorCode = AppErrorCode.VALIDATION_FAILED;
            break;
          case HttpStatus.UNAUTHORIZED:
            errorCode = AppErrorCode.UNAUTHORIZED;
            break;
          case HttpStatus.FORBIDDEN:
            errorCode = AppErrorCode.FORBIDDEN;
            break;
          case HttpStatus.NOT_FOUND:
            errorCode = AppErrorCode.RESOURCE_NOT_FOUND;
            break;
          case HttpStatus.CONFLICT:
            errorCode = AppErrorCode.RESOURCE_CONFLICT;
            break;
          case HttpStatus.TOO_MANY_REQUESTS:
            errorCode = AppErrorCode.RATE_LIMIT_EXCEEDED;
            break;
          case HttpStatus.SERVICE_UNAVAILABLE:
            errorCode = AppErrorCode.SERVICE_UNAVAILABLE;
            break;
        }
      }
    } else if (exception instanceof ZodError) {
      statusCode = HttpStatus.BAD_REQUEST;
      errorCode = AppErrorCode.VALIDATION_FAILED;
      message = 'Validation failed for one or more fields.';
      details = exception.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      }));
    } else if (exception instanceof DatabaseError || isDatabaseOperationError(exception)) {
      // CONFLICT-RESOLVED: Ánh xạ các lớp DatabaseError từ @sda/database sang mã trạng thái HTTP ngữ nghĩa (409/400/404/503) thay vì để lọt thành 500.
      const rawCode = extractRawDbErrorCode(exception);
      const mapped = exception instanceof DatabaseError ? exception : mapDatabaseError(exception);
      if (mapped instanceof DatabaseConflictError || rawCode === 'P2002' || rawCode === '23505') {
        statusCode = HttpStatus.CONFLICT;
        errorCode = AppErrorCode.RESOURCE_CONFLICT;
        message = mapped.message;
      } else if (mapped instanceof DatabaseConstraintError) {
        statusCode = HttpStatus.BAD_REQUEST;
        errorCode = AppErrorCode.VALIDATION_FAILED;
        message = mapped.message;
      } else if (mapped instanceof DatabaseNotFoundError) {
        statusCode = HttpStatus.NOT_FOUND;
        errorCode = AppErrorCode.RESOURCE_NOT_FOUND;
        message = mapped.message;
      } else if (mapped instanceof DatabaseUnavailableError) {
        statusCode = HttpStatus.SERVICE_UNAVAILABLE;
        errorCode = AppErrorCode.SERVICE_UNAVAILABLE;
        message = mapped.message;
      } else {
        const errorMsg = exception instanceof Error ? exception.message : String(exception);
        this.logger.error(`Database operation error [${correlationId}]: ${errorMsg}`, {
          correlationId,
        });
      }
    } else {
      // Unhandled error: log internally with correlation ID, never leak internal error to client
      const errorMsg = exception instanceof Error ? exception.message : String(exception);
      const stack = exception instanceof Error ? exception.stack : undefined;
      this.logger.error(`Unhandled server error [${correlationId}]: ${errorMsg}`, {
        correlationId,
        stack,
      });
    }

    const errorEnvelope: ErrorEnvelope = {
      statusCode,
      errorCode,
      message,
      correlationId,
      timestamp: new Date().toISOString(),
      ...(details !== undefined ? { details } : {}),
    };

    // Keep standard HTTP status code and attach correlation headers
    reply
      .status(statusCode)
      .header('x-correlation-id', correlationId)
      .header('x-request-id', correlationId)
      .header('cache-control', 'no-store')
      .send(errorEnvelope);
  }
}
