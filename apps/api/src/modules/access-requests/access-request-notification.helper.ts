/**
 * @module AccessRequestNotificationHelper
 * Algorithm / Thuật toán: Chuẩn Hóa Nội Dung & Phát Thông Báo Lũy Đẳng Tới Chủ Sở Hữu Tài Liệu Khi Có Yêu Cầu Mới Hoặc Hủy Yêu Cầu.
 * Cơ chế hoạt động:
 *   - Chỉ gửi khi `ownerId` tồn tại và khác `actorUserId` (tránh tự thông báo cho chính mình).
 *   - Dùng khóa khử trùng lặp tất định (`ACCESS_REQUEST_CREATED:<ownerId>:<requestId>` / `ACCESS_REQUEST_CANCELLED:<ownerId>:<requestId>`)
 *     để đảm bảo an toàn khi thử lại và bọc `try/catch` không làm hỏng giao dịch nghiệp vụ chính sau commit.
 */
import type { NotificationsService } from '../notifications/notifications.service.js';

function formatRequestedActionVi(action: string | undefined): string {
  return action?.toUpperCase() === 'DOWNLOAD' ? 'Tải về' : 'Chỉ xem';
}

function formatDocumentLabelVi(title?: string | null, documentCode?: string | null): string {
  if (!title) return 'của bạn';
  return `"${title}"${documentCode ? ` (${documentCode})` : ''}`;
}

/**
 * Thuật toán: Gửi thông báo đa kênh (`IN_APP` + `EMAIL` + SSE `NOTIFICATION_CREATED`) tới chủ sở hữu
 * ngay sau khi người đọc tạo yêu cầu xin cấp quyền truy cập tài liệu.
 */
export async function notifyOwnerOfAccessRequestCreated(params: {
  notifications?: NotificationsService | undefined;
  ownerId?: bigint | null | undefined;
  requesterId: bigint;
  requestId: string;
  documentId: string;
  documentTitle?: string | null | undefined;
  documentCode?: string | null | undefined;
  requestorName: string;
  requestorUsername: string;
  requestorDepartment?: string | null | undefined;
  requestedAction: 'VIEW' | 'DOWNLOAD';
  justification: string;
}): Promise<void> {
  const { notifications, ownerId, requesterId } = params;
  if (!notifications || !ownerId || ownerId === requesterId) return;

  const docLabel = formatDocumentLabelVi(params.documentTitle, params.documentCode);
  const actionLabel = formatRequestedActionVi(params.requestedAction);
  const deptSuffix =
    params.requestorDepartment && params.requestorDepartment !== 'Chung'
      ? ` (${params.requestorDepartment})`
      : '';
  const reasonSnippet = params.justification.trim();
  const reasonSuffix = reasonSnippet ? ` Lý do: ${reasonSnippet}` : '';

  try {
    await notifications.sendNotification({
      recipientId: ownerId,
      notificationType: 'ACCESS_REQUEST_CREATED',
      title: 'Yêu cầu cấp quyền truy cập tài liệu mới',
      body: `${params.requestorName}${deptSuffix} vừa gửi yêu cầu quyền "${actionLabel}" đối với tài liệu ${docLabel}.${reasonSuffix}`,
      relatedObjectType: 'ACCESS_REQUEST',
      relatedObjectId: params.requestId,
      deduplicationKey: `ACCESS_REQUEST_CREATED:${ownerId.toString()}:${params.requestId}`,
      payload: {
        requestId: params.requestId,
        documentId: params.documentId,
        documentCode: params.documentCode ?? null,
        requesterId: requesterId.toString(),
        requesterUsername: params.requestorUsername,
        requestedAction: params.requestedAction,
      },
    });
  } catch {
    // Non-fatal post-commit notification dispatch
  }
}

/**
 * Thuật toán: Gửi thông báo tới chủ sở hữu khi người đọc chủ động hủy yêu cầu truy cập đang chờ duyệt.
 */
export async function notifyOwnerOfAccessRequestCancelled(params: {
  notifications?: NotificationsService | undefined;
  ownerId?: bigint | null | undefined;
  requesterId: bigint;
  requestId: string;
  documentId: string;
  documentTitle?: string | null | undefined;
  documentCode?: string | null | undefined;
  requestorName: string;
  requestorUsername: string;
}): Promise<void> {
  const { notifications, ownerId, requesterId } = params;
  if (!notifications || !ownerId || ownerId === requesterId) return;

  const docLabel = formatDocumentLabelVi(params.documentTitle, params.documentCode);

  try {
    await notifications.sendNotification({
      recipientId: ownerId,
      notificationType: 'ACCESS_REQUEST_CANCELLED',
      title: 'Yêu cầu cấp quyền truy cập đã bị hủy',
      body: `${params.requestorName} đã hủy yêu cầu truy cập đang chờ phê duyệt đối với tài liệu ${docLabel}.`,
      relatedObjectType: 'ACCESS_REQUEST',
      relatedObjectId: params.requestId,
      deduplicationKey: `ACCESS_REQUEST_CANCELLED:${ownerId.toString()}:${params.requestId}`,
      payload: {
        requestId: params.requestId,
        documentId: params.documentId,
        documentCode: params.documentCode ?? null,
        requesterId: requesterId.toString(),
        requesterUsername: params.requestorUsername,
      },
    });
  } catch {
    // Non-fatal post-commit notification dispatch
  }
}
