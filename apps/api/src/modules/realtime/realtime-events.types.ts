/**
 * @module RealtimeEventsTypes
 * Thuật toán: Chuẩn Hóa Hợp Đồng Sự Kiện Thời Gian Thực Server-Sent Events (SSE) Theo Đối Tượng Đích (Zero-Trust Scoped Audience).
 */

export type RealtimeEventType =
  | 'NOTIFICATION_CREATED'
  | 'EXPORT_JOB_UPDATED'
  | 'ACCESS_REQUEST_UPDATED'
  | 'ACCESS_GRANT_UPDATED'
  | 'DOCUMENT_UPDATED'
  | 'SECURITY_ALERT_UPDATED'
  | 'INCIDENT_REPORT_UPDATED'
  | 'DETECTION_RULE_UPDATED'
  | 'ACCESS_SESSION_UPDATED'
  | 'USER_SESSION_REVOKED';

export interface RealtimeEventEnvelope<T = Record<string, unknown>> {
  id: string;
  type: RealtimeEventType;
  occurredAt: string;
  targetUserIds?: string[] | undefined;
  targetRoles?: string[] | undefined;
  targetDepartmentId?: string | null | undefined;
  targetSessionIds?: string[] | undefined;
  excludeSessionId?: string | undefined;
  excludeSessionIds?: string[] | undefined;
  payload: T;
}

export interface PublishRealtimeEventInput<T = Record<string, unknown>> {
  type: RealtimeEventType;
  targetUserIds?: readonly string[] | undefined;
  targetRoles?: readonly string[] | undefined;
  targetDepartmentId?: string | null | undefined;
  targetSessionIds?: readonly string[] | undefined;
  excludeSessionId?: string | undefined;
  excludeSessionIds?: readonly string[] | undefined;
  payload: T;
}

export interface RealtimeWirePayload<T = Record<string, unknown>> {
  id: string;
  type: RealtimeEventType;
  occurredAt: string;
  payload: T;
}
