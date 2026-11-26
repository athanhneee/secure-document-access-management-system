import { DlpEngine } from './dlp-engine.js';
import { hasEncapsulatedHttpBody } from './icap-http-body.js';
import {
  build204Response,
  buildBlockResponse,
  buildContinueResponse,
} from './icap-wire-responses.js';
import {
  persistNetworkDlpSecurityAlert,
  type IcapServerMetrics,
  type ResolvedIcapConfig,
} from './icap-alert-sink.js';
import { incrementIcapBlocked } from '../worker-metrics.js';
import type { DlpScanResult, IcapRequest } from './icap.types.js';

/**
 * Thuật toán: Đèn Hiệu Đếm FIFO Bất Đồng Bộ Không Khóa Bận (Bounded Async Inspection Semaphore).
 * Giới hạn tối đa `maxConcurrent` luồng giải nén và quét DLP chạy song song bảo vệ trần bộ nhớ `512m`.
 */
export class InspectionSemaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private readonly maxConcurrent = 16) {}

  public getActiveCount(): number {
    return this.active;
  }

  public async acquire(): Promise<() => void> {
    if (this.active < this.maxConcurrent) {
      this.active += 1;
    } else {
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve);
      });
      this.active += 1;
    }

    let released = false;
    return (): void => {
      if (released) return;
      released = true;
      this.active -= 1;
      const next = this.waiters.shift();
      if (next) next();
    };
  }
}

export interface ConnectionStreamState {
  continuedAfterPreview: boolean;
}

export type IcapEvaluationOutcome =
  { type: 'CONTINUE'; payload: Buffer } | { type: 'FINAL'; payload: Buffer };

export interface IcapRequestHandlerContext {
  readonly request: IcapRequest;
  readonly state: ConnectionStreamState;
  readonly keepAlive: boolean;
  readonly config: ResolvedIcapConfig;
  readonly metrics: IcapServerMetrics;
  readonly semaphore: InspectionSemaphore;
  readonly onViolationCallback?:
    ((violation: DlpScanResult, request: IcapRequest) => Promise<void> | void) | undefined;
}

/**
 * Thuật toán: Điều Phối Ghi Nhận Vi Phạm DLP Mạng (Callback tùy biến hoặc lưu `SecurityAlert` vào CSDL).
 */
async function notifyDlpViolation(
  scanResult: DlpScanResult,
  request: IcapRequest,
  onViolationCallback?: (violation: DlpScanResult, request: IcapRequest) => Promise<void> | void,
): Promise<void> {
  if (onViolationCallback) {
    try {
      await onViolationCallback(scanResult, request);
    } catch (err) {
      console.error('[ICAP Server] Error in violation callback:', err);
    }
    return;
  }
  await persistNetworkDlpSecurityAlert(scanResult, request);
}

/**
 * Thuật toán: Quét DLP bất đồng bộ dưới sự bảo vệ của `InspectionSemaphore` (`maxConcurrentInspections = 16`),
 * kiểm tra đầy đủ URI/query, HTTP headers, thân nén (`gzip`/`deflate`/`br`/`zstd`) và kho lưu trữ `.docx`/`.xlsx`.
 */
export async function executeIcapDlpEvaluation(
  ctx: IcapRequestHandlerContext,
): Promise<IcapEvaluationOutcome> {
  const { request, state, keepAlive, config, metrics, semaphore, onViolationCallback } = ctx;

  const hasEncapsulatedBody = hasEncapsulatedHttpBody(request.encapsulated);
  const isIncompletePreviewPhase = Boolean(
    hasEncapsulatedBody &&
    request.isPreview &&
    !request.isPreviewIof &&
    !state.continuedAfterPreview,
  );

  const release = await semaphore.acquire();
  let scanResult: DlpScanResult;
  try {
    const bodyContentEncoding =
      request.encapsulated.resBody !== undefined
        ? request.httpResponseHeaders !== undefined
          ? request.httpResponseHeaders['content-encoding']
          : request.httpHeaders?.['content-encoding']
        : request.encapsulated.reqBody !== undefined
          ? (request.httpRequestHeaders?.['content-encoding'] ??
            request.httpHeaders?.['content-encoding'])
          : undefined;

    scanResult = await DlpEngine.scanPayloadAsync(request.body, {
      customKeywords: config.customKeywords,
      action: config.action,
      contentEncoding: bodyContentEncoding,
      allowTruncatedPreview: isIncompletePreviewPhase,
      maxBodyBytes: config.maxBodyBytes,
      requestUri: request.uri,
      httpUri: request.httpUri,
      httpHeaders: request.httpHeaders,
      httpRequestHeaders: request.httpRequestHeaders,
      httpResponseHeaders: request.httpResponseHeaders,
      icapHeaders: request.headers,
    });
  } finally {
    release();
  }

  if (
    hasEncapsulatedBody &&
    request.isPreview &&
    !request.isPreviewIof &&
    !state.continuedAfterPreview &&
    scanResult.action !== 'BLOCK'
  ) {
    state.continuedAfterPreview = true;
    return { type: 'CONTINUE', payload: buildContinueResponse() };
  }

  metrics.totalRequests++;
  if (request.method === 'RESPMOD') metrics.respmodRequests++;
  else metrics.reqmodRequests++;
  metrics.scannedBytes += scanResult.scannedBytes;

  const safeUri = request.uri.replace(/\p{Cc}/gu, '').slice(0, 200);
  if (scanResult.action === 'BLOCK') {
    metrics.blockedViolations++;
    incrementIcapBlocked(1);
    console.warn(
      `[ICAP Server] DLP VIOLATION BLOCKED: ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
    );
    await notifyDlpViolation(scanResult, request, onViolationCallback);
    return { type: 'FINAL', payload: buildBlockResponse(scanResult.violations, { keepAlive }) };
  }

  if (scanResult.action === 'AUDIT' || !scanResult.isClean) {
    metrics.auditedViolations++;
    console.warn(
      `[ICAP Server] DLP VIOLATION AUDITED (pass-through): ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
    );
    await notifyDlpViolation(scanResult, request, onViolationCallback);
    return { type: 'FINAL', payload: build204Response({ keepAlive }) };
  }

  metrics.cleanPassThrough++;
  return { type: 'FINAL', payload: build204Response({ keepAlive }) };
}
