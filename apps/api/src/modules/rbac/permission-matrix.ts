export const SYSTEM_ROLE_PERMISSION_MATRIX = {
  SYSTEM_ADMIN: [
    'USER_MANAGE',
    'DEPARTMENT_MANAGE',
    'ROLE_MANAGE',
    'ATTRIBUTE_MANAGE',
    'POLICY_MANAGE',
    'POLICY_SIMULATE',
    'WATERMARK_CONFIG_MANAGE',
    'SYSTEM_HEALTH_VIEW',
  ],
  SECURITY_OFFICER: [
    'AUDIT_VIEW',
    'ALERT_VIEW',
    'ALERT_MANAGE',
    'WATERMARK_TRACE',
    'POLICY_SIMULATE',
    'INCIDENT_CREATE',
    'INCIDENT_MANAGE',
    'ACCESS_SESSION_TERMINATE',
  ],
  AUDITOR: ['AUDIT_VIEW', 'AUDIT_EXPORT', 'ALERT_VIEW', 'WATERMARK_TRACE', 'SYSTEM_REPORT_EXPORT'],
  DOCUMENT_OWNER: [
    'DOCUMENT_UPLOAD',
    'DOCUMENT_CLASSIFY',
    'DOCUMENT_VERSION_CREATE',
    'DOCUMENT_ARCHIVE',
    'ACCESS_REQUEST_DECIDE',
    'ACCESS_GRANT_CREATE',
    'ACCESS_GRANT_REVOKE',
    'ACCESS_GRANT_VIEW',
    'AUDIT_VIEW',
  ],
  DOCUMENT_READER: [
    'DOCUMENT_DISCOVER',
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
    'ACCESS_REQUEST_CREATE',
    'ACCESS_REQUEST_VIEW_OWN',
    'ACCESS_REQUEST_CANCEL',
    'NOTIFICATION_VIEW',
  ],
} as const;

export const PRIVILEGED_SEPARATION_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']);
const POLICY_SIMULATION_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER']);

export function canSimulatePolicy(roleCodes: readonly string[]): boolean {
  return roleCodes.some((roleCode) => POLICY_SIMULATION_ROLES.has(roleCode));
}

export function systemRoleAllows(roleCode: string, permissionCodes: string[]): boolean {
  const allowed =
    SYSTEM_ROLE_PERMISSION_MATRIX[roleCode as keyof typeof SYSTEM_ROLE_PERMISSION_MATRIX];
  return (
    allowed !== undefined &&
    permissionCodes.every((code) => (allowed as readonly string[]).includes(code))
  );
}
