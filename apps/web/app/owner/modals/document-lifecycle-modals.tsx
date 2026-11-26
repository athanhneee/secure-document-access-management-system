'use client';

import type { useDocumentHistory } from '../hooks/use-document-history';
import type { useDocumentLifecycle } from '../hooks/use-document-lifecycle';
import type {
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
  UserLookupItem,
} from '../types';
import { ArchiveDocumentModal } from './archive-document-modal';
import { ClassificationHistoryModal } from './classification-history-modal';
import { EditDocumentModal } from './edit-document-modal';
import { ReclassifyModal } from './reclassify-modal';
import { TransferOwnerModal } from './transfer-owner-modal';
import { UploadVersionModal } from './upload-version-modal';
import { VersionHistoryModal } from './version-history-modal';

interface DocumentLifecycleModalsProps {
  lifecycle: ReturnType<typeof useDocumentLifecycle>;
  history: ReturnType<typeof useDocumentHistory>;
  departments?: DepartmentLookupItem[] | undefined;
  eligibleTransferUsers?: UserLookupItem[] | undefined;
  canSetCurrentVersion?: boolean | undefined;
  classificationLevels: ClassificationLevelLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
  userClearanceRank?: number | null | undefined;
}

export function DocumentLifecycleModals({
  lifecycle,
  history,
  departments = [],
  eligibleTransferUsers = [],
  canSetCurrentVersion = false,
  classificationLevels,
  businessCategories,
  userClearanceRank,
}: DocumentLifecycleModalsProps) {
  return (
    <>
      <EditDocumentModal
        open={lifecycle.editMetaOpen}
        onOpenChange={lifecycle.setEditMetaOpen}
        document={lifecycle.docForEditMeta}
        departments={departments}
        title={lifecycle.editTitle}
        onTitleChange={lifecycle.setEditTitle}
        description={lifecycle.editDescription}
        onDescriptionChange={lifecycle.setEditDescription}
        departmentId={lifecycle.editDepartmentId}
        onDepartmentIdChange={lifecycle.setEditDepartmentId}
        retentionDate={lifecycle.editRetentionDate}
        onRetentionDateChange={lifecycle.setEditRetentionDate}
        isLoadingDetail={lifecycle.isLoadingEditMeta}
        isSaving={lifecycle.isSavingMetadata}
        onSubmit={lifecycle.handleConfirmEditMetadata}
      />

      <TransferOwnerModal
        open={lifecycle.transferOwnerOpen}
        onOpenChange={lifecycle.setTransferOwnerOpen}
        document={lifecycle.docForTransfer}
        eligibleUsers={eligibleTransferUsers}
        isLoadingUsers={lifecycle.isLoadingTransferUsers}
        newOwnerId={lifecycle.transferNewOwnerId}
        onNewOwnerIdChange={lifecycle.setTransferNewOwnerId}
        reason={lifecycle.transferReason}
        onReasonChange={lifecycle.setTransferReason}
        isTransferring={lifecycle.isTransferringOwner}
        onSubmit={lifecycle.handleConfirmTransferOwner}
      />

      <ReclassifyModal
        open={lifecycle.reclassifyOpen}
        onOpenChange={lifecycle.setReclassifyOpen}
        document={lifecycle.docForReclassify}
        reclassLevelId={lifecycle.reclassLevelId}
        onLevelChange={lifecycle.setReclassLevelId}
        reclassCategoryId={lifecycle.reclassCategoryId}
        onCategoryChange={lifecycle.setReclassCategoryId}
        reclassReason={lifecycle.reclassReason}
        onReasonChange={lifecycle.setReclassReason}
        isReclassifying={lifecycle.isReclassifying}
        onSubmit={lifecycle.handleConfirmReclassify}
        classificationLevels={classificationLevels}
        businessCategories={businessCategories}
        userClearanceRank={userClearanceRank}
      />

      <UploadVersionModal
        open={lifecycle.newVersionOpen}
        onOpenChange={lifecycle.setNewVersionOpen}
        document={lifecycle.docForNewVersion}
        newVersionFile={lifecycle.newVersionFile}
        onFileChange={lifecycle.setNewVersionFile}
        newVersionNote={lifecycle.newVersionNote}
        onNoteChange={lifecycle.setNewVersionNote}
        isUploading={lifecycle.isUploadingVersion}
        onSubmit={lifecycle.handleConfirmNewVersion}
      />

      <ArchiveDocumentModal
        open={lifecycle.archiveOpen}
        onOpenChange={lifecycle.setArchiveOpen}
        document={lifecycle.docForArchive}
        archiveReason={lifecycle.archiveReason}
        onReasonChange={lifecycle.setArchiveReason}
        isArchiving={lifecycle.isArchiving}
        onSubmit={lifecycle.handleConfirmArchive}
      />

      <VersionHistoryModal
        open={history.versionHistoryOpen}
        onOpenChange={history.setVersionHistoryOpen}
        document={history.docForVersions}
        versions={history.docVersions}
        isLoading={history.isLoadingVersions}
        canSetCurrentVersion={canSetCurrentVersion}
        settingVersionNo={lifecycle.settingVersionNo}
        onSetCurrentVersion={(doc, versionNo) => lifecycle.handleSetCurrentVersion(doc, versionNo)}
        onOpenClassHistory={(doc) => void history.handleOpenClassHistory(doc)}
      />

      <ClassificationHistoryModal
        open={history.classHistoryOpen}
        onOpenChange={history.setClassHistoryOpen}
        document={history.docForClassHistory}
        history={history.docClassHistory}
        isLoading={history.isLoadingClassHistory}
      />
    </>
  );
}
