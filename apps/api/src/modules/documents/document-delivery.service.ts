/**
 * Module: Controlled Document Delivery, Watermarked Preview & Single-Use Ticket Service
 * Algorithm: Orchestrates PEP session establishment, real-time zero-trust preview rendering,
 *   watermarked derivative downloads, and short-lived single-use CSPRNG download tickets.
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { CreateAccessSessionInput } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
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
  type DeliveryFileResult,
  type DownloadTicketEntry,
} from './delivery-ticket.helper.js';
import { executeWatermarkedPreview } from './delivery-preview.helper.js';
import { executeControlledDownload } from './delivery-download.helper.js';

export type { DeliveryFileResult } from './delivery-ticket.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class DocumentDeliveryService {
  private readonly database: PrismaClient;
  private readonly ticketTtlSeconds: number;
  // shortcut: 10,000 short-lived 60s single-use tickets (~3 MB) per replica, move to Redis GETDEL for multi-replica sticky-free redemption
  private readonly downloadTickets = new Map<string, DownloadTicketEntry>();

  constructor(
    private readonly pep: DocumentPepService,
    private readonly storage: ObjectStorageService,
    private readonly encryption: DocumentEncryptionService,
    private readonly officeConverter: OfficeConverterService,
    private readonly watermarkEngine: WatermarkEngineService,
    private readonly grantsService: AccessGrantsService,
    private readonly audit: DocumentDeliveryAuditService,
    config: AppConfigService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    this.ticketTtlSeconds = config.get('DOWNLOAD_TICKET_TTL_SECONDS') ?? 60;
  }

  /**
   * Algorithm: Controlled Access Session Creation via PEP
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
   * Algorithm: Session-Bound Watermarked PDF Preview Delivery
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
      documentId,
      sessionId,
      pageNumber,
      principal,
      context,
    });
  }

  /**
   * Algorithm: Controlled Derivative Document Download
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
   * Algorithm: Short-Lived Single-Use Download Ticket Issuance
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
      downloadTickets: this.downloadTickets,
      ticketTtlSeconds: this.ticketTtlSeconds,
      documentId,
      sessionId,
      principal,
      context,
    });
  }

  /**
   * Algorithm: Atomic Single-Use Download Ticket Redemption
   */
  async redeemDownloadTicket(ticket: string, context: RequestContext): Promise<DeliveryFileResult> {
    const entry = consumeSingleUseDownloadTicket(this.downloadTickets, ticket);
    return await this.downloadDocument(entry.documentId, entry.sessionId, entry.principal, context);
  }
}
