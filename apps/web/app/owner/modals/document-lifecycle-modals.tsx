'use client';

import type { useDocumentHistory } from '../hooks/use-document-history';
import type { useDocumentLifecycle } from '../hooks/use-document-lifecycle';
import type { BusinessCategoryLookupItem, ClassificationLevelLookupItem } from '../types';
import { ArchiveDocumentModal } from './archive-document-modal';
import { ClassificationHistoryModal } from './classification-history-modal';
import { ReclassifyModal } from './reclassify-modal';
import { UploadVersionModal } from './upload-version-modal';
import { VersionHistoryModal } from './version-history-modal';

interface DocumentLifecycleModalsProps {
  lifecycle: ReturnType<typeof useDocumentLifecycle>;
  history: ReturnType<typeof useDocumentHistory>;
  classificationLevels: ClassificationLevelLookupItem[];
  businessCategories: BusinessCategoryLookupItem[];
}

export function DocumentLifecycleModals({
  lifecycle,
  history,
  classificationLevels,
  businessCategories,
}: DocumentLifecycleModalsProps) {
  return (
    <>
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
