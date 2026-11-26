import type * as net from 'node:net';
import { IcapParser } from './icap-parser.js';
import { IcapChunkStreamTracker } from './icap-content-decoder.js';
import { hasEncapsulatedHttpBody } from './icap-http-body.js';
import { buildOptionsResponse, buildProtocolErrorResponse } from './icap-wire-responses.js';
import type { IcapServerMetrics, ResolvedIcapConfig } from './icap-alert-sink.js';
import {
  executeIcapDlpEvaluation,
  type ConnectionStreamState,
  type InspectionSemaphore,
} from './icap-request-handler.js';
import type { DlpScanResult, IcapRequest } from './icap.types.js';

const MAX_ICAP_HEADER_BYTES = 16 * 1024;
const MAX_CONNECTION_DURATION_MS = 60_000;
const BACKPRESSURE_PAUSE_BYTES = 1024 * 1024;

export interface IcapConnectionContext {
  readonly socket: net.Socket;
  readonly activeSockets: Set<net.Socket>;
  readonly config: ResolvedIcapConfig;
  readonly metrics: IcapServerMetrics;
  readonly semaphore: InspectionSemaphore;
  readonly getViolationCallback: () =>
    ((violation: DlpScanResult, request: IcapRequest) => Promise<void> | void) | undefined;
}

/**
 * Thuật toán: Máy trạng thái luồng TCP tuyến tính $O(N)$ rút cạn hàng đợi khung tin ICAP (`drainQueue`),
 * dừng sạch ngay tại `0\r\n\r\n` theo `request.consumedBytes` để bảo toàn nguyên vẹn các yêu cầu pipelined kế tiếp trên cùng kết nối `keep-alive`.
 */
export function attachIcapConnectionHandler(ctx: IcapConnectionContext): void {
  const { socket, activeSockets, config, metrics, semaphore, getViolationCallback } = ctx;
  activeSockets.add(socket);
  metrics.totalConnections++;

  let receivedChunks: Buffer[] = [];
  let newChunksForTracker: Buffer[] = [];
  let totalReceivedBytes = 0;
  let headersValidated = false;
  let isPreviewRequest = false;
  let bodyStartOffset = 0;
  let chunkTracker: IcapChunkStreamTracker | null = null;
  let drainRunning = false;
  let closedForProtocol = false;
  const state: ConnectionStreamState = { continuedAfterPreview: false };

  socket.setTimeout(30_000);
  const connectionDeadline = setTimeout(() => socket.destroy(), MAX_CONNECTION_DURATION_MS);
  connectionDeadline.unref();

  const replyAndClose = (payload: Buffer): void => {
    socket.write(payload, () => socket.end());
  };

  const consolidateBuffer = (): Buffer => {
    if (receivedChunks.length === 0) return Buffer.alloc(0);
    if (receivedChunks.length === 1) return receivedChunks[0]!;
    const merged = Buffer.concat(receivedChunks, totalReceivedBytes);
    receivedChunks = [merged];
    return merged;
  };

  const resetForRemainingBytes = (remaining: Buffer): void => {
    receivedChunks = remaining.length > 0 ? [Buffer.from(remaining)] : [];
    newChunksForTracker = [];
    totalReceivedBytes = remaining.length;
    headersValidated = false;
    isPreviewRequest = false;
    bodyStartOffset = 0;
    chunkTracker = null;
    state.continuedAfterPreview = false;
  };

  const drainQueue = async (): Promise<void> => {
    if (drainRunning || closedForProtocol) return;
    drainRunning = true;
    try {
      while (!closedForProtocol && totalReceivedBytes > 0) {
        let request: IcapRequest | null = null;

        if (!headersValidated) {
          const accumulated = consolidateBuffer();
          const icapHeaderEnd = accumulated.indexOf('\r\n\r\n');
          if (icapHeaderEnd === -1) {
            if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
              throw new Error('ICAP_400: ICAP header exceeds 16KiB');
            }
            break;
          }

          request = IcapParser.parseRequest(accumulated, {
            continuedAfterPreview: state.continuedAfterPreview,
          });
          if (!request || request.incompleteHeaders) {
            if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
              throw new Error('ICAP_400: Encapsulated headers exceed 16KiB');
            }
            break;
          }

          const bodyOffset = request.encapsulated.resBody ?? request.encapsulated.reqBody;
          const httpHeaderEnd = bodyOffset ?? request.encapsulated.nullBody ?? 0;
          if (icapHeaderEnd + 4 + httpHeaderEnd > MAX_ICAP_HEADER_BYTES) {
            throw new Error('ICAP_400: Combined headers exceed 16KiB');
          }

          if (request.method === 'OPTIONS') {
            metrics.totalRequests++;
            metrics.optionsRequests++;
            const consumed =
              request.consumedBytes ?? icapHeaderEnd + 4 + (request.encapsulated.nullBody ?? 0);
            const remaining = consolidateBuffer().subarray(consumed);
            const wantsKeepAlive = request.headers['connection']?.toLowerCase() === 'keep-alive';
            const resp = buildOptionsResponse(config, {
              keepAlive: wantsKeepAlive || remaining.length > 0,
            });
            resetForRemainingBytes(remaining);
            if (!wantsKeepAlive && remaining.length === 0) {
              closedForProtocol = true;
              replyAndClose(resp);
              return;
            }
            socket.write(resp);
            continue;
          }

          headersValidated = true;
          const hasEncapsulatedBody = hasEncapsulatedHttpBody(request.encapsulated);
          isPreviewRequest = Boolean(request.isPreview && hasEncapsulatedBody);
          newChunksForTracker = [];
          if (hasEncapsulatedBody && bodyOffset !== undefined) {
            bodyStartOffset = icapHeaderEnd + 4 + bodyOffset;
            chunkTracker = new IcapChunkStreamTracker();
            if (bodyStartOffset < accumulated.length) {
              chunkTracker.feed(accumulated.subarray(bodyStartOffset), 1);
            }
          }
          if (!request.isComplete) break;
        } else {
          const requiredZeros = isPreviewRequest && state.continuedAfterPreview ? 2 : 1;
          while (newChunksForTracker.length > 0) {
            chunkTracker?.feed(newChunksForTracker.shift()!, requiredZeros);
          }
          if (
            chunkTracker &&
            chunkTracker.zeroChunksCompleted < requiredZeros &&
            !chunkTracker.hasIeofTerminator
          ) {
            break;
          }
          request = IcapParser.parseRequest(consolidateBuffer(), {
            continuedAfterPreview: state.continuedAfterPreview,
          });
          if (!request || request.incompleteHeaders || !request.isComplete) break;
        }

        const consumed = request.consumedBytes ?? totalReceivedBytes;
        const wantsKeepAlive = request.headers['connection']?.toLowerCase() === 'keep-alive';
        const hadPipelinedBytesBeforeEval = totalReceivedBytes > consumed;
        const keepAlive = wantsKeepAlive || hadPipelinedBytesBeforeEval;
        const outcome = await executeIcapDlpEvaluation({
          request,
          state,
          keepAlive,
          config,
          metrics,
          semaphore,
          onViolationCallback: getViolationCallback(),
        });

        if (outcome.type === 'CONTINUE') {
          socket.write(outcome.payload);
          const fullAfterContinue = consolidateBuffer();
          newChunksForTracker = [];
          chunkTracker = new IcapChunkStreamTracker();
          if (bodyStartOffset < fullAfterContinue.length) {
            chunkTracker.feed(fullAfterContinue.subarray(bodyStartOffset), 2);
          }
          if (chunkTracker.zeroChunksCompleted < 2 && !chunkTracker.hasIeofTerminator) break;
          continue;
        }

        const remaining = consolidateBuffer().subarray(consumed);
        resetForRemainingBytes(remaining);
        if (!keepAlive) {
          closedForProtocol = true;
          replyAndClose(outcome.payload);
          return;
        }
        socket.write(outcome.payload);
      }
    } catch (err) {
      closedForProtocol = true;
      const message = err instanceof Error ? err.message : String(err);
      if (message.startsWith('ICAP_405:')) return replyAndClose(buildProtocolErrorResponse(405));
      if (message.startsWith('ICAP_400:')) return replyAndClose(buildProtocolErrorResponse(400));
      console.error('[ICAP Server] Error processing message:', err);
      replyAndClose(buildProtocolErrorResponse(500));
    } finally {
      drainRunning = false;
      if (!closedForProtocol && !socket.destroyed) socket.resume();
    }
  };

  socket.on('data', (chunk: Buffer) => {
    if (closedForProtocol) return;
    if (totalReceivedBytes + chunk.length > config.maxBodyBytes) {
      closedForProtocol = true;
      replyAndClose(buildProtocolErrorResponse(400));
      return;
    }
    receivedChunks.push(chunk);
    totalReceivedBytes += chunk.length;
    if (headersValidated && chunkTracker) newChunksForTracker.push(chunk);
    if (drainRunning && totalReceivedBytes > BACKPRESSURE_PAUSE_BYTES) socket.pause();
    void drainQueue();
  });

  socket.on('timeout', () => socket.destroy());
  socket.on('error', () => socket.destroy());
  socket.on('close', () => {
    clearTimeout(connectionDeadline);
    activeSockets.delete(socket);
  });
}
