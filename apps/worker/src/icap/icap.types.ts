/**
 * Thuật toán / Tổng quan module:
 * Định nghĩa hệ thống kiểu dữ liệu tĩnh và hợp đồng giao thức RFC 3507 ICAP (Internet Content Adaptation Protocol)
 * phục vụ máy chủ kiểm soát thất thoát dữ liệu biên mạng (Network DLP), bao gồm phương thức ICAP,
 * vị trí byte-offset của phần thân đóng gói (`EncapsulatedSection`), độ dài khung đã tiêu thụ (`consumedBytes`)
 * cho kết nối tái sử dụng keep-alive / pipelining và cấu hình giải nén bất đồng bộ giới hạn đồng thời.
 */
export type IcapMethod = 'OPTIONS' | 'RESPMOD' | 'REQMOD';

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

export interface DlpScanOptions {
  customKeywords?: string[] | undefined;
  action?: 'BLOCK' | 'AUDIT_ONLY' | undefined;
  contentEncoding?: string | undefined;
  allowTruncatedPreview?: boolean | undefined;
  maxBodyBytes?: number | undefined;
  requestUri?: string | undefined;
  httpUri?: string | undefined;
  httpHeaders?: Record<string, string> | undefined;
  httpRequestHeaders?: Record<string, string> | undefined;
  httpResponseHeaders?: Record<string, string> | undefined;
  icapHeaders?: Record<string, string> | undefined;
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
  httpRequestHeaders?: Record<string, string> | undefined;
  httpResponseHeaders?: Record<string, string> | undefined;
  httpMethod?: string | undefined;
  httpUri?: string | undefined;
  httpStatusCode?: number | undefined;
  httpStatusMessage?: string | undefined;
  body: Buffer;
  readonly incompleteHeaders?: boolean | undefined;
  isComplete: boolean;
  consumedBytes?: number | undefined;
  isPreview?: boolean | undefined;
  isPreviewIof?: boolean | undefined;
  continuedAfterPreview?: boolean | undefined;
}

export interface IcapServerConfig {
  enabled?: boolean | undefined;
  port?: number | undefined;
  host?: string | undefined;
  serviceName?: string | undefined;
  maxConnections?: number | undefined;
  maxConcurrentInspections?: number | undefined;
  maxBodyBytes?: number | undefined;
  previewSize?: number | undefined;
  action?: 'BLOCK' | 'AUDIT_ONLY' | undefined;
  customKeywords?: string[] | undefined;
}
