import {
  type ArgumentsHost,
  type ExceptionFilter,
  Catch,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { AppErrorCode, type ErrorEnvelope } from '@sda/contracts';
import { JsonLoggerService } from '../logger/json-logger.service.js';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new JsonLoggerService(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const reply = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const correlationId =
      request.correlationId ??
      (typeof request.headers['x-correlation-id'] === 'string'
        ? request.headers['x-correlation-id']
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
