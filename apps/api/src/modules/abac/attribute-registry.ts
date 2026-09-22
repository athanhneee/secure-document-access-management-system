import type { AttributeDescriptor, AttributeType } from './abac.types.js';

export const ATTRIBUTE_CODE_TO_KEY: Readonly<Record<string, string>> = {
  CLEARANCE_LEVEL: 'subject.clearanceRank',
  SUBJECT_DEPARTMENT: 'subject.departmentId',
  EMPLOYMENT_STATUS: 'subject.employmentStatus',
  PROJECT: 'subject.projects',
  CLASSIFICATION_RANK: 'resource.classificationRank',
  RESOURCE_OWNER: 'resource.ownerId',
  RESOURCE_DEPARTMENT: 'resource.departmentId',
  RESOURCE_CATEGORY: 'resource.category',
  RESOURCE_STATUS: 'resource.status',
  CURRENT_TIME: 'environment.currentTime',
  SOURCE_IP: 'environment.ip',
  TRUSTED_NETWORK: 'environment.trustedNetwork',
  DEVICE_TRUST: 'environment.deviceTrust',
  MFA: 'environment.mfa',
  RISK_SCORE: 'environment.riskScore',
};

export const CONTEXT_ATTRIBUTES: Readonly<Record<string, AttributeDescriptor>> = {
  'subject.clearanceRank': descriptor('subject.clearanceRank', 'NUMBER', true),
  'subject.departmentId': descriptor('subject.departmentId', 'STRING', true),
  'subject.employmentStatus': descriptor('subject.employmentStatus', 'STRING', true),
  'subject.projects': descriptor('subject.projects', 'STRING', false),
  'resource.classificationRank': descriptor('resource.classificationRank', 'NUMBER', true),
  'resource.ownerId': descriptor('resource.ownerId', 'STRING', true),
  'resource.departmentId': descriptor('resource.departmentId', 'STRING', true),
  'resource.category': descriptor('resource.category', 'STRING', true),
  'resource.status': descriptor('resource.status', 'STRING', true),
  'environment.currentTime': descriptor('environment.currentTime', 'DATE', true),
  'environment.ip': descriptor('environment.ip', 'IP', true),
  'environment.trustedNetwork': descriptor('environment.trustedNetwork', 'BOOLEAN', true),
  'environment.deviceTrust': descriptor('environment.deviceTrust', 'BOOLEAN', true),
  'environment.mfa': descriptor('environment.mfa', 'BOOLEAN', true),
  'environment.riskScore': descriptor('environment.riskScore', 'NUMBER', true),
};

function descriptor(key: string, type: AttributeType, required: boolean): AttributeDescriptor {
  return { key, type, required };
}
