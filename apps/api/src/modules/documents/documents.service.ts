import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateDocumentDraftInput,
  type UpdateDocumentMetadataInput,
  type ReclassifyDocumentInput,
  type SetCurrentVersionInput,
  type TransferDocumentOwnerInput,
  type ArchiveDocumentInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { AuthorizationCache } from '../rbac/authorization-cache.js';
import { DocumentAuditService } from './document-audit.service.js';

export interface DocumentDetail {
  id: string;
  documentCode: string;
  title: string;
  description: string | null;
  ownerId: string;
  ownerUsername?: string;
  departmentId: string;
  departmentName?: string;
  status: string;
  discoverable: boolean;
  retentionUntil: string | null;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
  currentVersionId: string | null;
  currentVersion?: {
    id: string;
    versionNo: number;
    originalFilename: string;
    mimeType: string;
    fileSizeBytes: string;
    sha256Hash: string;
    scanStatus: string;
    createdAt: string;
  } | null;
  currentClassification?: {
    id: string;
    classificationLevelId: string;
    classificationLevelCode: string;
    classificationLevelName: string;
    rank: number;
    businessCategoryId: string;
    businessCategoryCode: string;
    businessCategoryName: string;
    reason: string | null;
    classifiedBy: string;
    effectiveFrom: string;
  } | null;
}

@Injectable()
export class DocumentsService {
  private readonly database: ReturnType<typeof getDatabaseClient>;

  constructor(
    private readonly audit: DocumentAuditService,
    private readonly authorization: AuthorizationService,
    private readonly cache: AuthorizationCache,
    databaseClient?: ReturnType<typeof getDatabaseClient>,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as ReturnType<typeof getDatabaseClient>;
    }
  }

  /**
   * Enforces Requirement 9:
   * Only the document owner or an authorized business administrator for this department
   * may modify document metadata or lifecycle status.
   * Technical admin (SYSTEM_ADMIN) does not inherently become owner.
   */
  async assertDocumentMutationPermission(
    document: { id: string; owner_id: bigint; department_id: bigint },
    principal: AuthPrincipal,
  ): Promise<void> {
    // 1. Document owner always has mutation rights on their document
    if (document.owner_id === principal.userId) {
      return;
    }

    // 2. Otherwise, check for business administration permissions scoped to document's department
    const hasClassify = await this.authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', {
      targetDepartmentId: document.department_id,
    });
    const hasManage = await this.authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', {
      targetDepartmentId: document.department_id,
    });
    const hasArchive = await this.authorization.hasPermission(principal, 'DOCUMENT', 'ARCHIVE', {
      targetDepartmentId: document.department_id,
    });

    if (hasClassify || hasManage || hasArchive) {
      return;
    }

    // 3. Technical admin without business permission in department scope is denied
    throw new ForbiddenException({
      errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
      message:
        'Only the document owner or an authorized business administrator for this department may modify this document.',
    });
  }

  /**
   * Requirement 1: Create document in DRAFT status.
   */
  async createDocumentDraft(
    input: CreateDocumentDraftInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const trimmedTitle = input.title.trim();
    if (!trimmedTitle) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Document title cannot be empty.',
      });
    }

    // Validate department exists and is active
    const dept = await this.database.department.findUnique({
      where: { id: input.departmentId },
    });
    if (!dept || !dept.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target department does not exist or is inactive.',
      });
    }

    // Validate classification level if provided
    if (input.classificationLevelId) {
      const level = await this.database.classificationLevel.findUnique({
        where: { id: input.classificationLevelId },
      });
      if (!level || !level.is_active) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target classification level does not exist or is inactive.',
        });
      }
    }

    // Validate business category if provided
    if (input.businessCategoryId) {
      const cat = await this.database.businessCategory.findUnique({
        where: { id: input.businessCategoryId },
      });
      if (!cat || !cat.is_active) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target business category does not exist or is inactive.',
        });
      }
    }

    let retentionDate: Date | null = null;
    if (input.retentionUntil) {
      retentionDate = new Date(`${input.retentionUntil}T00:00:00.000Z`);
      if (Number.isNaN(retentionDate.getTime())) {
        throw new BadRequestException({
          errorCode: AppErrorCode.RETENTION_DATE_INVALID,
          message: 'Invalid retention date format.',
        });
      }
    }

    const documentId = randomUUID();
    const docCode = input.documentCode ?? `DOC-${randomUUID().substring(0, 8).toUpperCase()}`;

    await this.database.$transaction(async (tx) => {
      await tx.document.create({
        data: {
          id: documentId,
          document_code: docCode,
          title: trimmedTitle,
          description: input.description ?? null,
          owner_id: principal.userId,
          department_id: input.departmentId,
          status: 'DRAFT',
          discoverable: true,
          retention_until: retentionDate,
        },
      });

      if (input.classificationLevelId && input.businessCategoryId) {
        await tx.documentClassificationHistory.create({
          data: {
            document_id: documentId,
            classification_level_id: input.classificationLevelId,
            business_category_id: input.businessCategoryId,
            reason: input.reason ?? 'Initial draft classification',
            classified_by: principal.userId,
            effective_from: new Date(),
            effective_to: null,
          },
        });
      }
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_CREATED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          documentCode: docCode,
          title: trimmedTitle,
          departmentId: input.departmentId.toString(),
          classificationLevelId: input.classificationLevelId?.toString() ?? null,
          businessCategoryId: input.businessCategoryId?.toString() ?? null,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 9: Update document metadata.
   * Only owner or business admin. Technical admin is rejected.
   */
  async updateMetadata(
    documentId: string,
    input: UpdateDocumentMetadataInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
    });
    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Cannot modify an archived or deleted document.',
      });
    }

    await this.assertDocumentMutationPermission(doc, principal);

    const updateData: {
      title?: string;
      description?: string | null;
      department_id?: bigint;
      retention_until?: Date | null;
      version: { increment: number };
    } = {
      version: { increment: 1 },
    };

    if (input.title !== undefined) {
      const trimmed = input.title.trim();
      if (!trimmed) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Title cannot be empty.',
        });
      }
      updateData.title = trimmed;
    }

    if (input.description !== undefined) {
      updateData.description = input.description;
    }

    if (input.departmentId !== undefined) {
      const dept = await this.database.department.findUnique({
        where: { id: input.departmentId },
      });
      if (!dept || !dept.is_active) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target department does not exist or is inactive.',
        });
      }
      updateData.department_id = input.departmentId;
    }

    if (input.retentionUntil !== undefined) {
      if (input.retentionUntil === null) {
        updateData.retention_until = null;
      } else {
        const retDate = new Date(`${input.retentionUntil}T00:00:00.000Z`);
        if (Number.isNaN(retDate.getTime())) {
          throw new BadRequestException({
            errorCode: AppErrorCode.RETENTION_DATE_INVALID,
            message: 'Invalid retention date format.',
          });
        }
        updateData.retention_until = retDate;
      }
    }

    await this.database.document.update({
      where: { id: documentId },
      data: updateData,
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_METADATA_UPDATED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          title: input.title ?? null,
          departmentId: input.departmentId ? input.departmentId.toString() : null,
          retentionUntil: input.retentionUntil ?? null,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 2: Only versions with scan_status CLEAN can be assigned as current_version_id.
   * Cannot point current_version to a version of a different document.
   */
  async setCurrentVersion(
    documentId: string,
    input: SetCurrentVersionInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
    });
    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Cannot update version of an archived or deleted document.',
      });
    }

    await this.assertDocumentMutationPermission(doc, principal);

    let version;
    if (input.versionId) {
      version = await this.database.documentVersion.findUnique({
        where: { id: input.versionId },
      });
    } else if (input.versionNo) {
      version = await this.database.documentVersion.findUnique({
        where: {
          document_id_version_no: {
            document_id: documentId,
            version_no: input.versionNo,
          },
        },
      });
    } else {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Must provide either versionId or versionNo.',
      });
    }

    if (!version) {
      throw new NotFoundException({
        errorCode: AppErrorCode.VERSION_NOT_FOUND,
        message: 'Document version not found.',
      });
    }

    // Acceptance criteria: Không thể trỏ current_version sang version của document khác
    if (version.document_id !== documentId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_VERSION_TARGET,
        message: 'Cannot point current_version to a version belonging to a different document.',
      });
    }

    // Acceptance criteria: Chỉ phiên bản scan_status CLEAN mới được gán current_version_id
    if (version.scan_status !== 'CLEAN') {
      throw new BadRequestException({
        errorCode: AppErrorCode.VERSION_NOT_CLEAN,
        message: `Version cannot be assigned as current version because its scan status is ${version.scan_status}. Only CLEAN versions are allowed.`,
      });
    }

    await this.database.document.update({
      where: { id: documentId },
      data: {
        current_version_id: version.id,
        version: { increment: 1 },
      },
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_CURRENT_VERSION_SET',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        versionNo: version.version_no,
        details: {
          versionId: version.id.toString(),
          versionNo: version.version_no,
          scanStatus: version.scan_status,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 4: SCD Type 2 classification history (effective_from / effective_to).
   * Requirement 5: Reclassification to higher confidentiality level re-evaluates active grants,
   *                revokes/suspends grants that fail clearance, terminates active sessions.
   * Requirement 6: Reclassification to lower confidentiality level does NOT automatically expand old grants.
   */
  async reclassifyDocument(
    documentId: string,
    input: ReclassifyDocumentInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
    });
    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Cannot reclassify an archived or deleted document.',
      });
    }

    await this.assertDocumentMutationPermission(doc, principal);

    const targetLevel = await this.database.classificationLevel.findUnique({
      where: { id: input.classificationLevelId },
    });
    if (!targetLevel || !targetLevel.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target classification level does not exist or is inactive.',
      });
    }

    const targetCategory = await this.database.businessCategory.findUnique({
      where: { id: input.businessCategoryId },
    });
    if (!targetCategory || !targetCategory.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target business category does not exist or is inactive.',
      });
    }

    const now = new Date();
    let oldRank = 0;
    const newRank = targetLevel.rank;
    let isLevelIncrease = false;
    let revokedGrantsCount = 0;
    let terminatedSessionsCount = 0;

    await this.database.$transaction(async (tx) => {
      // Concurrency lock: lock the document row FOR UPDATE
      if (
        typeof (tx as unknown as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function'
      ) {
        await (
          tx as unknown as {
            $executeRawUnsafe: (sql: string, ...args: unknown[]) => Promise<unknown>;
          }
        ).$executeRawUnsafe('SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE', documentId);
      }

      // Find current active classification record (effective_to IS NULL)
      const current = await tx.documentClassificationHistory.findFirst({
        where: {
          document_id: documentId,
          effective_to: null,
        },
        include: { classification_levels: true },
      });

      if (current) {
        oldRank = current.classification_levels.rank;
        isLevelIncrease = newRank > oldRank;

        // Close the current classification row (SCD Type 2)
        await tx.documentClassificationHistory.update({
          where: { id: current.id },
          data: { effective_to: now },
        });
      }

      // Create new classification row (effective_from = now, effective_to = null)
      await tx.documentClassificationHistory.create({
        data: {
          document_id: documentId,
          classification_level_id: targetLevel.id,
          business_category_id: targetCategory.id,
          reason: input.reason,
          classified_by: principal.userId,
          effective_from: now,
          effective_to: null,
        },
      });

      // Requirement 5: If confidentiality level increased, re-evaluate all active grants
      if (isLevelIncrease) {
        const activeGrants = await tx.accessGrant.findMany({
          where: {
            document_id: documentId,
            status: 'ACTIVE',
          },
        });

        for (const grant of activeGrants) {
          if (grant.principal_type === 'USER' && grant.principal_user_id) {
            // Find user's active clearance rank
            const clearanceAssignment = await tx.userAttributeAssignment.findFirst({
              where: {
                user_id: grant.principal_user_id,
                attribute_definitions: { code: 'CLEARANCE_LEVEL' },
                valid_from: { lte: now },
                OR: [{ valid_to: null }, { valid_to: { gt: now } }],
              },
              include: { attribute_options: true },
              orderBy: { attribute_options: { numeric_rank: 'desc' } },
            });

            const userRank = clearanceAssignment?.attribute_options?.numeric_rank ?? 0;

            if (userRank < newRank) {
              // Grant fails new clearance requirement -> REVOKE
              await tx.accessGrant.update({
                where: { id: grant.id },
                data: {
                  status: 'REVOKED',
                  revoked_by: principal.userId,
                  revoked_at: now,
                  revoke_reason:
                    'Reclassification to higher confidentiality level: user clearance insufficient',
                  version: { increment: 1 },
                },
              });
              revokedGrantsCount++;

              // Terminate all associated active sessions immediately
              const terminatedSessions = await tx.accessSession.updateMany({
                where: {
                  access_grant_id: grant.id,
                  status: 'ACTIVE',
                },
                data: {
                  status: 'TERMINATED',
                  ended_at: now,
                  terminated_reason:
                    'Document reclassified to higher level: clearance no longer sufficient',
                },
              });
              terminatedSessionsCount += terminatedSessions.count;

              // Invalidate user authorization cache
              this.cache.invalidateUser(grant.principal_user_id);
            }
          } else if (grant.principal_type === 'ROLE') {
            // For role grants, terminate active sessions where the user's clearance < newRank
            const roleSessions = await tx.accessSession.findMany({
              where: {
                access_grant_id: grant.id,
                status: 'ACTIVE',
              },
            });

            for (const sess of roleSessions) {
              const sessionUserClearance = await tx.userAttributeAssignment.findFirst({
                where: {
                  user_id: sess.user_id,
                  attribute_definitions: { code: 'CLEARANCE_LEVEL' },
                  valid_from: { lte: now },
                  OR: [{ valid_to: null }, { valid_to: { gt: now } }],
                },
                include: { attribute_options: true },
                orderBy: { attribute_options: { numeric_rank: 'desc' } },
              });
              const sessRank = sessionUserClearance?.attribute_options?.numeric_rank ?? 0;
              if (sessRank < newRank) {
                await tx.accessSession.update({
                  where: { id: sess.id },
                  data: {
                    status: 'TERMINATED',
                    ended_at: now,
                    terminated_reason:
                      'Document reclassified to higher level: role member clearance insufficient',
                  },
                });
                terminatedSessionsCount++;
                this.cache.invalidateUser(sess.user_id);
              }
            }
          }
        }
      }
      // Requirement 6: If confidentiality level decreased (newRank < oldRank),
      // we do NOT automatically restore or expand past grants. They remain as-is.
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_RECLASSIFIED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          oldRank,
          newRank,
          targetLevelCode: targetLevel.code,
          targetCategoryCode: targetCategory.code,
          isLevelIncrease,
          revokedGrantsCount,
          terminatedSessionsCount,
          reason: input.reason,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 1: Transition document to ACTIVE status.
   * Must have: owner, department, title, business category, and classification.
   * Requirement 2: current_version_id must have scan_status CLEAN.
   */
  async activateDocument(
    documentId: string,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
      include: {
        users: true,
        departments: true,
        current_version: true,
        classification_history: {
          where: { effective_to: null },
          include: {
            classification_levels: true,
            business_categories: true,
          },
        },
      },
    });

    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ACTIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ALREADY_ACTIVE,
        message: 'Document is already active.',
      });
    }

    if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Archived or deleted document cannot be activated.',
      });
    }

    await this.assertDocumentMutationPermission(doc, principal);

    // 1. Validate Owner
    if (!doc.owner_id || !doc.users || doc.users.status !== 'ACTIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
        message: 'Document must have an active owner before activation.',
      });
    }

    // 2. Validate Department
    if (!doc.department_id || !doc.departments || !doc.departments.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
        message: 'Document must belong to an active department before activation.',
      });
    }

    // 3. Validate Title
    if (!doc.title || doc.title.trim().length === 0) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
        message: 'Document title cannot be empty before activation.',
      });
    }

    // 4. Validate Classification & Business Category
    const activeClassification = doc.classification_history?.[0];
    if (
      !activeClassification ||
      !activeClassification.classification_level_id ||
      !activeClassification.business_category_id
    ) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
        message:
          'Document must have an active classification level and business category before activation.',
      });
    }

    // 5. Validate Current Version & CLEAN scan status
    if (!doc.current_version_id || !doc.current_version) {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
        message: 'Document must have a current file version assigned before activation.',
      });
    }

    if (doc.current_version.scan_status !== 'CLEAN') {
      throw new BadRequestException({
        errorCode: AppErrorCode.VERSION_NOT_CLEAN,
        message: `Cannot activate document: current version has scan status ${doc.current_version.scan_status}. Only CLEAN versions can be activated.`,
      });
    }

    await this.database.document.update({
      where: { id: documentId },
      data: {
        status: 'ACTIVE',
        version: { increment: 1 },
      },
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_ACTIVATED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          currentVersionId: doc.current_version.id.toString(),
          classificationLevel: activeClassification.classification_levels.code,
          businessCategory: activeClassification.business_categories.code,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 7: Archive document.
   * Changes status to ARCHIVED, sets archived_at (satisfies DB check constraint),
   * suspends active grants, terminates active sessions, and blocks new requests.
   */
  async archiveDocument(
    documentId: string,
    input: ArchiveDocumentInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
    });
    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ARCHIVED') {
      return this.getDocumentById(documentId);
    }

    await this.assertDocumentMutationPermission(doc, principal);

    const now = new Date();
    let suspendedGrantsCount = 0;
    let terminatedSessionsCount = 0;

    await this.database.$transaction(async (tx) => {
      // Set status = 'ARCHIVED' and archived_at = now
      await tx.document.update({
        where: { id: documentId },
        data: {
          status: 'ARCHIVED',
          archived_at: now,
          version: { increment: 1 },
        },
      });

      // Suspend all active access grants
      const grantsResult = await tx.accessGrant.updateMany({
        where: {
          document_id: documentId,
          status: 'ACTIVE',
        },
        data: {
          status: 'SUSPENDED',
          revoked_by: principal.userId,
          revoked_at: now,
          revoke_reason: input.reason ?? 'Document archived',
        },
      });
      suspendedGrantsCount = grantsResult.count;

      // Terminate all active access sessions for this document's versions
      const versions = await tx.documentVersion.findMany({
        where: { document_id: documentId },
        select: { id: true },
      });
      const versionIds = versions.map((v) => v.id);

      if (versionIds.length > 0) {
        const sessionsResult = await tx.accessSession.updateMany({
          where: {
            document_version_id: { in: versionIds },
            status: 'ACTIVE',
          },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Document archived',
          },
        });
        terminatedSessionsCount = sessionsResult.count;
      }
    });

    this.cache.invalidateAll();

    await this.audit.record(
      {
        action: 'DOCUMENT_ARCHIVED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          suspendedGrantsCount,
          terminatedSessionsCount,
          reason: input.reason ?? 'Document archived',
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Transfer document ownership to another user.
   */
  async transferOwner(
    documentId: string,
    input: TransferDocumentOwnerInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id: documentId },
    });
    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Cannot transfer ownership of an archived or deleted document.',
      });
    }

    await this.assertDocumentMutationPermission(doc, principal);

    const targetUser = await this.database.user.findUnique({
      where: { id: input.newOwnerId },
    });
    if (!targetUser || targetUser.status !== 'ACTIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target user does not exist or is not active.',
      });
    }

    const previousOwnerId = doc.owner_id;

    await this.database.document.update({
      where: { id: documentId },
      data: {
        owner_id: input.newOwnerId,
        version: { increment: 1 },
      },
    });

    await this.audit.record(
      {
        action: 'DOCUMENT_OWNER_TRANSFERRED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId,
        details: {
          previousOwnerId: previousOwnerId.toString(),
          newOwnerId: input.newOwnerId.toString(),
          reason: input.reason,
        },
      },
      context,
    );

    return this.getDocumentById(documentId);
  }

  /**
   * Requirement 8: Retention check warning job.
   * Scans documents approaching or past retention_until.
   * Generates notifications and security alerts.
   * CRITICAL: MUST NEVER automatically delete files without approval policy!
   */
  async checkRetentionWarnings(daysThreshold = 30): Promise<{
    processedCount: number;
    warningCount: number;
    warnings: Array<{
      documentId: string;
      documentCode: string;
      retentionUntil: string;
      daysRemaining: number;
    }>;
  }> {
    const now = new Date();
    const thresholdDate = new Date(now.getTime() + daysThreshold * 86400 * 1000);

    const expiringDocuments = await this.database.document.findMany({
      where: {
        status: { notIn: ['DELETED'] },
        retention_until: {
          not: null,
          lte: thresholdDate,
        },
      },
      include: {
        users: { select: { id: true, username: true } },
      },
    });

    const warnings: Array<{
      documentId: string;
      documentCode: string;
      retentionUntil: string;
      daysRemaining: number;
    }> = [];

    for (const doc of expiringDocuments) {
      if (!doc.retention_until) continue;

      const retTime = doc.retention_until.getTime();
      const diffMs = retTime - now.getTime();
      const daysRemaining = Math.ceil(diffMs / (86400 * 1000));
      const dateStr = doc.retention_until.toISOString().substring(0, 10);

      // Create owner notification
      await this.database.notification.create({
        data: {
          id: randomUUID(),
          recipient_id: doc.owner_id,
          notification_type: 'RETENTION_EXPIRATION_WARNING',
          title: 'Cảnh báo hạn lưu trữ tài liệu',
          body: `Tài liệu "${doc.title}" (${doc.document_code}) sẽ hết hạn lưu trữ vào ngày ${dateStr} (${daysRemaining <= 0 ? 'đã hết hạn' : `còn ${daysRemaining} ngày`}). Cần xem xét chính sách phê duyệt lưu trữ hoặc tiêu hủy.`,
          related_object_type: 'DOCUMENT',
          related_object_id: doc.id,
          status: 'UNREAD',
        },
      });

      // If already expired, generate a SecurityAlert for review
      if (daysRemaining <= 0) {
        await this.database.securityAlert.create({
          data: {
            id: randomUUID(),
            alert_type: 'RETENTION_OVERDUE',
            severity: 'MEDIUM',
            status: 'OPEN',
            title: `Tài liệu quá hạn lưu trữ: ${doc.document_code}`,
            description: `Tài liệu "${doc.title}" (${doc.document_code}) đã quá hạn lưu trữ ngày ${dateStr}. Không tự xóa file khi chưa có chính sách phê duyệt.`,
            document_id: doc.id,
            detected_user_id: doc.owner_id,
          },
        });
      }

      // Record audit log
      await this.audit.record(
        {
          action: 'DOCUMENT_RETENTION_WARNING',
          outcome: 'SUCCESS',
          actorUserId: doc.owner_id,
          actorUsername: doc.users?.username ?? 'system',
          documentId: doc.id,
          details: {
            documentCode: doc.document_code,
            retentionUntil: dateStr,
            daysRemaining,
          },
        },
        {
          ip: '127.0.0.1',
          correlationId: randomUUID(),
          userAgent: 'sda-retention-job/1.0',
        },
      );

      warnings.push({
        documentId: doc.id,
        documentCode: doc.document_code,
        retentionUntil: dateStr,
        daysRemaining,
      });
    }

    return {
      processedCount: expiringDocuments.length,
      warningCount: warnings.length,
      warnings,
    };
  }

  /**
   * Fetch single document detail.
   */
  async getDocumentById(id: string): Promise<DocumentDetail> {
    const doc = await this.database.document.findUnique({
      where: { id },
      include: {
        users: { select: { id: true, username: true } },
        departments: { select: { id: true, name: true } },
        current_version: true,
        classification_history: {
          where: { effective_to: null },
          include: {
            classification_levels: true,
            business_categories: true,
          },
        },
      },
    });

    if (!doc) {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    const activeClassification = doc.classification_history?.[0];

    return {
      id: doc.id,
      documentCode: doc.document_code,
      title: doc.title,
      description: doc.description,
      ownerId: doc.owner_id.toString(),
      ownerUsername: doc.users?.username,
      departmentId: doc.department_id.toString(),
      departmentName: doc.departments?.name,
      status: doc.status,
      discoverable: doc.discoverable,
      retentionUntil: doc.retention_until
        ? doc.retention_until.toISOString().substring(0, 10)
        : null,
      archivedAt: doc.archived_at ? doc.archived_at.toISOString() : null,
      createdAt: doc.created_at ? doc.created_at.toISOString() : new Date().toISOString(),
      updatedAt: doc.updated_at ? doc.updated_at.toISOString() : new Date().toISOString(),
      currentVersionId: doc.current_version_id ? doc.current_version_id.toString() : null,
      currentVersion: doc.current_version
        ? {
            id: doc.current_version.id.toString(),
            versionNo: doc.current_version.version_no,
            originalFilename: doc.current_version.original_filename,
            mimeType: doc.current_version.mime_type,
            fileSizeBytes: doc.current_version.file_size_bytes.toString(),
            sha256Hash: doc.current_version.sha256_hash,
            scanStatus: doc.current_version.scan_status,
            createdAt: doc.current_version.created_at
              ? doc.current_version.created_at.toISOString()
              : new Date().toISOString(),
          }
        : null,
      currentClassification: activeClassification
        ? {
            id: activeClassification.id.toString(),
            classificationLevelId: activeClassification.classification_level_id.toString(),
            classificationLevelCode: activeClassification.classification_levels.code,
            classificationLevelName: activeClassification.classification_levels.name,
            rank: activeClassification.classification_levels.rank,
            businessCategoryId: activeClassification.business_category_id.toString(),
            businessCategoryCode: activeClassification.business_categories.code,
            businessCategoryName: activeClassification.business_categories.name,
            reason: activeClassification.reason,
            classifiedBy: activeClassification.classified_by.toString(),
            effectiveFrom: activeClassification.effective_from
              ? activeClassification.effective_from.toISOString()
              : new Date().toISOString(),
          }
        : null,
    };
  }

  /**
   * Requirement 4: List full SCD Type 2 classification history for auditability.
   */
  async getClassificationHistory(documentId: string): Promise<
    Array<{
      id: string;
      classificationLevelId: string;
      classificationLevelCode: string;
      classificationLevelName: string;
      rank: number;
      businessCategoryId: string;
      businessCategoryCode: string;
      businessCategoryName: string;
      reason: string | null;
      classifiedBy: string;
      effectiveFrom: string;
      effectiveTo: string | null;
    }>
  > {
    const history = await this.database.documentClassificationHistory.findMany({
      where: { document_id: documentId },
      include: {
        classification_levels: true,
        business_categories: true,
      },
      orderBy: { effective_from: 'asc' },
    });

    return history.map((item) => ({
      id: item.id.toString(),
      classificationLevelId: item.classification_level_id.toString(),
      classificationLevelCode: item.classification_levels.code,
      classificationLevelName: item.classification_levels.name,
      rank: item.classification_levels.rank,
      businessCategoryId: item.business_category_id.toString(),
      businessCategoryCode: item.business_categories.code,
      businessCategoryName: item.business_categories.name,
      reason: item.reason,
      classifiedBy: item.classified_by.toString(),
      effectiveFrom: item.effective_from.toISOString(),
      effectiveTo: item.effective_to ? item.effective_to.toISOString() : null,
    }));
  }

  /**
   * List all versions of a document.
   */
  async getDocumentVersions(documentId: string): Promise<
    Array<{
      id: string;
      versionNo: number;
      originalFilename: string;
      mimeType: string;
      fileSizeBytes: string;
      sha256Hash: string;
      scanStatus: string;
      changeNote: string | null;
      uploadedBy: string;
      createdAt: string;
    }>
  > {
    const versions = await this.database.documentVersion.findMany({
      where: { document_id: documentId },
      orderBy: { version_no: 'desc' },
    });

    return versions.map((v) => ({
      id: v.id.toString(),
      versionNo: v.version_no,
      originalFilename: v.original_filename,
      mimeType: v.mime_type,
      fileSizeBytes: v.file_size_bytes.toString(),
      sha256Hash: v.sha256_hash,
      scanStatus: v.scan_status,
      changeNote: v.change_note,
      uploadedBy: v.uploaded_by.toString(),
      createdAt: v.created_at.toISOString(),
    }));
  }

  /**
   * Search / list documents.
   */
  async listDocuments(): Promise<{ data: unknown[] }> {
    const docs = await this.database.document.findMany({
      where: { status: { notIn: ['DELETED'] } },
      take: 50,
      orderBy: { created_at: 'desc' },
    });
    return { data: docs };
  }
}
