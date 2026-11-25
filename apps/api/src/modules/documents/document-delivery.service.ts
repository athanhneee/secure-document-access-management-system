/**
 * Module: Controlled Document Delivery, Watermarked Preview & Distributed Single-Use Ticket Service
 * Thuật toán: Điều Phối Phân Phối Tài Liệu Có Kiểm Soát (`DocumentDeliveryService`).
 *   1. Mở phiên truy cập qua cổng PEP Zero-Trust (`createSession`).
 *   2. Phục vụ xem trước PDF nhúng watermark có bộ đệm phiên mã hóa trên `STORAGE_BUCKET_DERIVATIVES` (`getPreviewPdf`).
 *   3. Phát hành và đổi vé tải dùng một lần nguyên tử qua `DistributedStateService` kèm tái xác minh CSDL thời gian thực (`createDownloadTicket` / `redeemDownloadTicket`).
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { CreateAccessSessionInput } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentPepService, type PepEvaluationResult } from './document-pep.service.js';
import { OfficeConverterService } from './office-converter.service.js';
import { WatermarkEngineService } from '../watermarks/watermark-engine.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';
import { AccessGrantsService } from '../access-grants/access-grants.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import {
  consumeSingleUseDownloadTicket,
  issueShortLivedDownloadTicket,
  reverifyRedeemedTicketState,
  type DeliveryFileResult,
} from './delivery-ticket.helper.js';
import { executeWatermarkedPreview } from './delivery-preview.helper.js';
import { executeControlledDownload } from './delivery-download.helper.js';

export type { DeliveryFileResult } from './delivery-ticket.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class DocumentDeliveryService {
  private readonly database: PrismaClient;
  private readonly ticketTtlSeconds: number;
  private readonly stateStore: DistributedStateService;

  constructor(
    private readonly pep: DocumentPepService,
    private readonly storage: ObjectStorageService,
    private readonly encryption: DocumentEncryptionService,
    private readonly officeConverter: OfficeConverterService,
    private readonly watermarkEngine: WatermarkEngineService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    private readonly config: AppConfigService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() stateStore?: DistributedStateService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    const rawTtl =
      typeof config?.get === 'function' ? config.get('DOWNLOAD_TICKET_TTL_SECONDS') : undefined;
    this.ticketTtlSeconds = typeof rawTtl === 'number' && Number.isFinite(rawTtl) ? rawTtl : 60;
    this.stateStore =
      stateStore ??
      new DistributedStateService(config instanceof AppConfigService ? config : undefined);
  }

  /**
   * Thuật toán: Thiết lập phiên truy cập tài liệu có kiểm soát thông qua cổng thực thi chính sách PEP.
   */
  async createSession(
    documentId: string,
    input: CreateAccessSessionInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<PepEvaluationResult> {
    return await this.pep.enforceAccess(documentId, principal, context, {
      action: input.action,
      grantId: input.grantId,
      deviceFingerprint: input.deviceFingerprint,
    });
  }

  /**
   * Thuật toán: Phục vụ xem trước PDF gắn watermark truy vết và tối ưu chuyển trang qua bộ đệm dẫn xuất mã hóa.
   */
  async getPreviewPdf(
    documentId: string,
    sessionId: string,
    pageNumber: number | undefined,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DeliveryFileResult> {
    return await executeWatermarkedPreview({
      database: this.database,
      pep: this.pep,
      storage: this.storage,
      encryption: this.encryption,
      officeConverter: this.officeConverter,
      watermarkEngine: this.watermarkEngine,
      grantsService: this.grantsService,
      audit: this.audit,
      stateStore: this.stateStore,
      config: this.config,
      documentId,
      sessionId,
      pageNumber,
      principal,
      context,
    });
  }

  /**
   * Thuật toán: Thực thi tải xuống bản dẫn xuất tài liệu đã kiểm định quyền `DOWNLOAD` và đóng watermark bắt buộc.
   */
  async downloadDocument(
    documentId: string,
    sessionId: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DeliveryFileResult> {
    return await executeControlledDownload({
      database: this.database,
      pep: this.pep,
      storage: this.storage,
      encryption: this.encryption,
      officeConverter: this.officeConverter,
      watermarkEngine: this.watermarkEngine,
      grantsService: this.grantsService,
      audit: this.audit,
      documentId,
      sessionId,
      principal,
      context,
    });
  }

  /**
   * Thuật toán: Phát hành vé tải dùng một lần ngắn hạn (`DT-<64hex>`) lưu phân tán trên `DistributedStateService`.
   */
  async createDownloadTicket(
    documentId: string,
    sessionId: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<{ ticket: string; expiresAt: string; ttlSeconds: number }> {
    return await issueShortLivedDownloadTicket({
      database: this.database,
      pep: this.pep,
      grantsService: this.grantsService,
      stateStore: this.stateStore,
      ticketTtlSeconds: this.ticketTtlSeconds,
      documentId,
      sessionId,
      principal,
      context,
    });
  }

  /**
   * Thuật toán: Tiêu thụ nguyên tử một lần vé tải và tái xác minh trực tiếp CSDL (`AccessSession`, `AccessGrant`, `User`, IP) trước khi truyền tệp.
   */
  async redeemDownloadTicket(ticket: string, context: RequestContext): Promise<DeliveryFileResult> {
    const entry = await consumeSingleUseDownloadTicket(this.stateStore, ticket);
    await reverifyRedeemedTicketState({
      database: this.database,
      grantsService: this.grantsService,
      entry,
      context,
      now: new Date(),
    });
    return await this.downloadDocument(entry.documentId, entry.sessionId, entry.principal, context);
  }
}
