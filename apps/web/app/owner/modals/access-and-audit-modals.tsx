'use client';

import type { useOwnerDelivery } from '../hooks/use-owner-delivery';
import type { useOwnerGrants } from '../hooks/use-owner-grants';
import type { useOwnerRequests } from '../hooks/use-owner-requests';
import type { AuditLogItem, DocumentItem, RoleLookupItem, UserLookupItem } from '../types';
import { AuditDetailModal } from './audit-detail-modal';
import { CreateGrantModal } from './create-grant-modal';
import { DecideRequestModal } from './decide-request-modal';
import { ForensicPreviewModal } from './forensic-preview-modal';
import { RevokeGrantModal } from './revoke-grant-modal';

interface AccessAndAuditModalsProps {
  grantsControl: ReturnType<typeof useOwnerGrants>;
  requestsControl: ReturnType<typeof useOwnerRequests>;
  delivery: ReturnType<typeof useOwnerDelivery>;
  documents: DocumentItem[];
  usersLookup: UserLookupItem[];
  rolesLookup: RoleLookupItem[];
  auditDetailOpen: boolean;
  onAuditDetailOpenChange: (open: boolean) => void;
  selectedAuditLog: AuditLogItem | null;
  userFullName?: string | null | undefined;
  username?: string | null | undefined;
}

export function AccessAndAuditModals({
  grantsControl,
  requestsControl,
  delivery,
  documents,
  usersLookup,
  rolesLookup,
  auditDetailOpen,
  onAuditDetailOpenChange,
  selectedAuditLog,
  userFullName,
  username,
}: AccessAndAuditModalsProps) {
  return (
    <>
      <CreateGrantModal
        grantsControl={grantsControl}
        documents={documents}
        usersLookup={usersLookup}
        rolesLookup={rolesLookup}
      />
      <RevokeGrantModal
        open={grantsControl.revokeOpen}
        onOpenChange={grantsControl.setRevokeOpen}
        grant={grantsControl.selectedGrant}
        revokeReason={grantsControl.revokeReason}
        onReasonChange={grantsControl.setRevokeReason}
        isRevoking={grantsControl.isRevoking}
        onSubmit={grantsControl.handleConfirmRevoke}
      />
      <DecideRequestModal
        open={requestsControl.approveOpen}
        onOpenChange={requestsControl.setApproveOpen}
        request={requestsControl.selectedRequest}
        grantAction={requestsControl.grantAction}
        onActionChange={requestsControl.setGrantAction}
        grantValidDays={requestsControl.grantValidDays}
        onValidDaysChange={requestsControl.setGrantValidDays}
        isApproving={requestsControl.isApproving}
        onConfirmApprove={() => void requestsControl.handleConfirmApprove()}
      />
      <AuditDetailModal
        open={auditDetailOpen}
        onOpenChange={onAuditDetailOpenChange}
        auditLog={selectedAuditLog}
      />
      <ForensicPreviewModal
        open={delivery.previewOpen}
        onOpenChange={delivery.handleClosePreview}
        document={delivery.previewDoc}
        sessionId={delivery.previewSessionId}
        pdfUrl={delivery.previewPdfUrl}
        page={delivery.previewPage}
        totalPages={delivery.previewTotalPages}
        isLoading={delivery.isLoadingPreview}
        userFullName={userFullName}
        username={username}
        onPageChange={(p) => void delivery.handlePageChange(p)}
      />
    </>
  );
}
