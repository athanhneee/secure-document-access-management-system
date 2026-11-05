/**
 * Module: Document Lifecycle Domain DTOs & Detail Projection Helper
 * Algorithm: Projects relational Prisma `Document` entities (owner, department, current version,
 *   active SCD Type 2 classification) into normalized API DTOs after anti-enumeration read verification.
 */
import { NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { assertDocumentReadAccess } from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

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

export interface ClassificationHistoryItem {
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
}

export interface DocumentVersionItem {
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
}

export interface RetentionCheckResult {
  processedCount: number;
  warningCount: number;
  warnings: Array<{
    documentId: string;
    documentCode: string;
    retentionUntil: string;
    daysRemaining: number;
  }>;
}

/**
 * Algorithm: Anti-Enumeration Document Detail Hydration
 * Loads document relations, enforces `assertDocumentReadAccess(..., allowDiscoverable = true)`, and maps to `DocumentDetail`.
 */
export async function queryDocumentDetailById(
  database: PrismaClient,
  authorization: AuthorizationService,
  id: string,
  principal?: AuthPrincipal,
): Promise<DocumentDetail> {
  const doc = await database.document.findUnique({
    where: { id },
    include: {
      users: { select: { id: true, username: true } },
      departments: { select: { id: true, name: true } },
      current_version: true,
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true, business_categories: true },
      },
    },
  });

  if (!doc) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  await assertDocumentReadAccess(database, authorization, doc, principal, true);

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
    retentionUntil: doc.retention_until ? doc.retention_until.toISOString().substring(0, 10) : null,
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
          fileSizeBytes: doc.current_version.file_size_bytes?.toString() ?? '0',
          sha256Hash: doc.current_version.sha256_hash,
          scanStatus: doc.current_version.scan_status,
          createdAt: doc.current_version.created_at
            ? doc.current_version.created_at.toISOString()
            : new Date().toISOString(),
        }
      : null,
    currentClassification: activeClassification
      ? {
          id: activeClassification.id ? activeClassification.id.toString() : '',
          classificationLevelId: activeClassification.classification_level_id
            ? activeClassification.classification_level_id.toString()
            : '',
          classificationLevelCode: activeClassification.classification_levels?.code ?? '',
          classificationLevelName: activeClassification.classification_levels?.name ?? '',
          rank: activeClassification.classification_levels?.rank ?? 0,
          businessCategoryId: activeClassification.business_category_id
            ? activeClassification.business_category_id.toString()
            : '',
          businessCategoryCode: activeClassification.business_categories?.code ?? '',
          businessCategoryName: activeClassification.business_categories?.name ?? '',
          reason: activeClassification.reason ?? '',
          classifiedBy: activeClassification.classified_by
            ? activeClassification.classified_by.toString()
            : '',
          effectiveFrom: activeClassification.effective_from
            ? activeClassification.effective_from.toISOString()
            : new Date().toISOString(),
        }
      : null,
  };
}
