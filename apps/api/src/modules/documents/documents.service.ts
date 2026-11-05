/**
 * Module: Document Lifecycle, SCD Type 2 Classification & Retention Facade Service
 * Algorithm: Coordinates scoped document authorization, `DRAFT -> ACTIVE -> ARCHIVED` lifecycle transitions,
 *   SCD Type 2 confidentiality reclassification with cascading grant/session revocation, ownership handover,
 *   and non-destructive retention horizon checks.
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type {
  ArchiveDocumentInput,
  CreateDocumentDraftInput,
  ReclassifyDocumentInput,
  SetCurrentVersionInput,
  TransferDocumentOwnerInput,
  UpdateDocumentMetadataInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { AuthorizationCache } from '../rbac/authorization-cache.js';
import { DocumentAuditService } from './document-audit.service.js';
import {
  queryDocumentDetailById,
  type ClassificationHistoryItem,
  type DocumentDetail,
  type DocumentVersionItem,
  type RetentionCheckResult,
} from './documents.types.js';
import { assertDocumentMutationPermission as checkMutationPermission } from './document-access-guard.helper.js';
import {
  executeCreateDocumentDraft,
  executeUpdateDocumentMetadata,
} from './document-lifecycle.helper.js';
import {
  executeActivateDocument,
  executeArchiveDocument,
} from './document-lifecycle-transitions.helper.js';
import { executeSetCurrentVersion, queryDocumentVersions } from './document-versions.helper.js';
import {
  executeReclassifyDocument,
  queryClassificationHistory,
} from './document-classification.helper.js';
import { executeTransferDocumentOwner } from './document-ownership.helper.js';
import { executeCheckRetentionWarnings } from './document-retention.helper.js';

export type { DocumentDetail } from './documents.types.js';

@Injectable()
export class DocumentsService {
  private readonly database: ReturnType<typeof getDatabaseClient>;

  constructor(
    private readonly audit: DocumentAuditService,
    private readonly authorization: AuthorizationService,
    private readonly cache: AuthorizationCache,
    @Optional() databaseClient?: ReturnType<typeof getDatabaseClient>,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as ReturnType<typeof getDatabaseClient>;
    }
  }

  /**
   * Algorithm: Scoped Document Mutation Authorization Gate
   */
  async assertDocumentMutationPermission(
    document: { id: string; owner_id: bigint; department_id: bigint },
    principal: AuthPrincipal,
  ): Promise<void> {
    await checkMutationPermission(this.authorization, document, principal);
  }

  async createDocumentDraft(
    input: CreateDocumentDraftInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const documentId = await executeCreateDocumentDraft({
      database: this.database,
      audit: this.audit,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async updateMetadata(
    documentId: string,
    input: UpdateDocumentMetadataInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeUpdateDocumentMetadata({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      documentId,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async setCurrentVersion(
    documentId: string,
    input: SetCurrentVersionInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeSetCurrentVersion({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      documentId,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async reclassifyDocument(
    documentId: string,
    input: ReclassifyDocumentInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeReclassifyDocument({
      database: this.database,
      authorization: this.authorization,
      cache: this.cache,
      audit: this.audit,
      documentId,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async activateDocument(
    documentId: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeActivateDocument({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      documentId,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async archiveDocument(
    documentId: string,
    input: ArchiveDocumentInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeArchiveDocument({
      database: this.database,
      authorization: this.authorization,
      cache: this.cache,
      audit: this.audit,
      documentId,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async transferOwner(
    documentId: string,
    input: TransferDocumentOwnerInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    await executeTransferDocumentOwner({
      database: this.database,
      authorization: this.authorization,
      cache: this.cache,
      audit: this.audit,
      documentId,
      input,
      principal,
      context,
    });
    return this.getDocumentById(documentId);
  }

  async checkRetentionWarnings(
    daysThreshold = 30,
    principal?: AuthPrincipal,
    context?: RequestContext,
  ): Promise<RetentionCheckResult> {
    return executeCheckRetentionWarnings({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      daysThreshold,
      principal,
      context,
    });
  }

  async getDocumentById(id: string, principal?: AuthPrincipal): Promise<DocumentDetail> {
    return queryDocumentDetailById(this.database, this.authorization, id, principal);
  }

  async getClassificationHistory(
    documentId: string,
    principal?: AuthPrincipal,
  ): Promise<ClassificationHistoryItem[]> {
    return queryClassificationHistory(this.database, this.authorization, documentId, principal);
  }

  async getDocumentVersions(
    documentId: string,
    principal?: AuthPrincipal,
  ): Promise<DocumentVersionItem[]> {
    return queryDocumentVersions(this.database, this.authorization, documentId, principal);
  }
}
