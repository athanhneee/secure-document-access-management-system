import type * as net from 'node:net';
import { DlpEngine } from './dlp-engine.js';
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
import type { DlpScanResult, IcapRequest } from './icap.types.js';

export interface ConnectionStreamState {
  isProcessing: boolean;
  continuedAfterPreview: boolean;
}

export interface IcapRequestHandlerContext {
  readonly socket: net.Socket;
  readonly request: IcapRequest;
  readonly state: ConnectionStreamState;
  readonly config: ResolvedIcapConfig;
  readonly metrics: IcapServerMetrics;
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
 * Thuật toán: Quét DLP và phản hồi khung tin `REQMOD`/`RESPMOD` đã hoàn chỉnh (bao gồm thương lượng Preview `100 Continue`,
 * chặn `HTTP 403` ở chế độ `BLOCK`, và ghi cảnh báo `AUDIT_ONLY` kèm `204 No modifications`).
 */
export async function executeIcapDlpEvaluation(ctx: IcapRequestHandlerContext): Promise<void> {
  const { socket, request, state, config, metrics, onViolationCallback } = ctx;

  const scanResult = DlpEngine.scanPayload(request.body, {
    customKeywords: config.customKeywords,
    action: config.action,
  });

  if (
    request.isPreview &&
    !request.isPreviewIof &&
    !state.continuedAfterPreview &&
    scanResult.action !== 'BLOCK'
  ) {
    state.continuedAfterPreview = true;
    socket.write(buildContinueResponse());
    return;
  }

  state.isProcessing = true;
  socket.pause();
  metrics.totalRequests++;
  if (request.method === 'RESPMOD') metrics.respmodRequests++;
  else metrics.reqmodRequests++;
  metrics.scannedBytes += scanResult.scannedBytes;

  const replyAndClose = (payload: Buffer): void => {
    socket.write(payload, () => socket.end());
  };

  const safeUri = request.uri.replace(/\p{Cc}/gu, '').slice(0, 200);
  if (scanResult.action === 'BLOCK') {
    metrics.blockedViolations++;
    console.warn(
      `[ICAP Server] DLP VIOLATION BLOCKED: ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
    );
    await notifyDlpViolation(scanResult, request, onViolationCallback);
    replyAndClose(buildBlockResponse(scanResult.violations));
    return;
  }

  if (scanResult.action === 'AUDIT' || !scanResult.isClean) {
    metrics.auditedViolations++;
    console.warn(
      `[ICAP Server] DLP VIOLATION AUDITED (pass-through): ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
    );
    await notifyDlpViolation(scanResult, request, onViolationCallback);
    replyAndClose(build204Response());
    return;
  }

  metrics.cleanPassThrough++;
  replyAndClose(build204Response());
}
