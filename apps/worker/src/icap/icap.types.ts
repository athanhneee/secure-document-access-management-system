export type IcapMethod = 'OPTIONS' | 'RESPMOD' | 'REQMOD';

export type IcapStatusCode = 200 | 204 | 400 | 403 | 404 | 405 | 500;

export type DlpSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type DlpViolationType =
  | 'TOP_SECRET_CLASSIFICATION'
  | 'PRIVATE_KEY_CREDENTIAL'
  | 'FORENSIC_WATERMARK_LEAK'
  | 'PAYMENT_CARD_DATA'
  | 'CITIZEN_IDENTITY_DATA'
  | 'CUSTOM_POLICY_KEYWORD';

export type DlpPolicyAction = 'ALLOW' | 'BLOCK' | 'AUDIT';

export interface DlpViolation {
  type: DlpViolationType;
  severity: DlpSeverity;
  rule: string;
  description: string;
  matchedSnippet: string;
}

export interface DlpScanResult {
  action: DlpPolicyAction;
  violations: DlpViolation[];
  scannedBytes: number;
  isClean: boolean;
}

export interface EncapsulatedSection {
  reqHdr?: number | undefined;
  reqBody?: number | undefined;
  resHdr?: number | undefined;
  resBody?: number | undefined;
  nullBody?: number | undefined;
}

export interface IcapRequest {
  method: IcapMethod;
  uri: string;
  version: string;
  headers: Record<string, string>;
  encapsulated: EncapsulatedSection;
  previewBytes?: number | undefined;
  httpHeaders?: Record<string, string> | undefined;
  httpMethod?: string | undefined;
  httpUri?: string | undefined;
  httpStatusCode?: number | undefined;
  httpStatusMessage?: string | undefined;
  body: Buffer;
  isComplete: boolean;
}

export interface IcapServerConfig {
  enabled?: boolean | undefined;
  port?: number | undefined;
  host?: string | undefined;
  serviceName?: string | undefined;
  maxConnections?: number | undefined;
  previewSize?: number | undefined;
  action?: 'BLOCK' | 'AUDIT_ONLY' | undefined;
  customKeywords?: string[] | undefined;
}
