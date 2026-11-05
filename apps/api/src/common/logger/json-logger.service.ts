/**
 * Module: Dịch vụ Nhật ký Cấu trúc JSON (Structured NDJSON Logger Service)
 * Thuật toán: Hợp nhất siêu dữ liệu ngữ cảnh, che dấu đệ quy dữ liệu nhạy cảm và điều phối luồng xuất chuẩn.
 */
import { Injectable, type LoggerService } from '@nestjs/common';
import { redactSensitiveData } from './redaction.js';

export interface LogEntry {
  level: string;
  time: string;
  msg: string;
  context?: string;
  correlationId?: string;
  [key: string]: unknown;
}

@Injectable()
export class JsonLoggerService implements LoggerService {
  private context: string | undefined;

  constructor(context?: string) {
    this.context = context;
  }

  setContext(context: string): void {
    this.context = context;
  }

  log(message: unknown, ...optionalParams: unknown[]): void {
    this.writeLog('info', message, optionalParams);
  }

  error(message: unknown, ...optionalParams: unknown[]): void {
    this.writeLog('error', message, optionalParams);
  }

  warn(message: unknown, ...optionalParams: unknown[]): void {
    this.writeLog('warn', message, optionalParams);
  }

  debug(message: unknown, ...optionalParams: unknown[]): void {
    this.writeLog('debug', message, optionalParams);
  }

  verbose(message: unknown, ...optionalParams: unknown[]): void {
    this.writeLog('trace', message, optionalParams);
  }

  /**
   * Thuật toán: Tổng hợp Ngữ cảnh, Che dấu Dữ liệu Nhạy cảm và Tuần tự hóa NDJSON
   * Mục đích: Chuẩn hóa các tham số log đa kiểu của NestJS thành một dòng JSON duy nhất (NDJSON)
   *   đã được lọc sạch thông tin mật và gắn mã tương quan truy vết.
   * Cơ chế hoạt động:
   *   - Duyệt tuần tự `optionalParams`: tham số kiểu chuỗi được nhận diện làm tên ngữ cảnh (`context`),
   *     còn tham số kiểu đối tượng được gộp vào `extraData` đồng thời trích xuất `correlationId` nếu có.
   *   - Áp dụng `redactSensitiveData` cho cả `message` dạng đối tượng và `extraData` trước khi đóng gói.
   *   - Tuần tự hóa bản ghi `LogEntry` kèm dấu thời gian ISO-8601 và định tuyến xuất ra `stderr` đối với
   *     mức `error`, hoặc `stdout` đối với các mức độ còn lại.
   */
  private writeLog(level: string, message: unknown, optionalParams: unknown[]): void {
    let context = this.context;
    let correlationId: string | undefined;
    let extraData: Record<string, unknown> = {};

    for (const param of optionalParams) {
      if (typeof param === 'string') {
        context = param;
      } else if (typeof param === 'object' && param !== null) {
        const obj = param as Record<string, unknown>;
        if (typeof obj['correlationId'] === 'string') {
          correlationId = obj['correlationId'];
        }
        extraData = { ...extraData, ...obj };
      }
    }

    if (typeof message === 'object' && message !== null) {
      const msgObj = message as Record<string, unknown>;
      if (typeof msgObj['correlationId'] === 'string') {
        correlationId = msgObj['correlationId'];
      }
    }

    const safeMessage =
      typeof message === 'string'
        ? message
        : (redactSensitiveData(message) as Record<string, unknown>);

    const safeExtra = redactSensitiveData(extraData) as Record<string, unknown>;

    const logEntry: LogEntry = {
      level,
      time: new Date().toISOString(),
      msg: typeof safeMessage === 'string' ? safeMessage : JSON.stringify(safeMessage),
      ...(context ? { context } : {}),
      ...(correlationId ? { correlationId } : {}),
      ...safeExtra,
    };

    const output = JSON.stringify(logEntry);
    if (level === 'error') {
      process.stderr.write(`${output}\n`);
    } else {
      process.stdout.write(`${output}\n`);
    }
  }
}
