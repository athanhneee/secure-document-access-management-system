/**
 * Module: Multi-Provider Envelope KMS Contracts & Combined Key Reference Parser
 * Thuật toán: Giao Diện Trừu Tượng Bọc/Giải Bọc Khóa Phong Bì (`KmsService`) & Tách Chuỗi Tham Chiếu Khóa Từ Phải Sang Trái.
 *   1. Định nghĩa hợp đồng `wrapKey`, `unwrapKey` (hỗ trợ tùy chọn ngữ cảnh xác thực `aad`) và `unwrapCombinedRef`.
 *   2. Tách chuỗi `<provider>:<key-id>:<wrapped-dek>` tại dấu `:` cuối cùng để bảo toàn nguyên vẹn dấu `:` bên trong `keyRef` (ví dụ `vault:rotated-kek:v2`).
 */

export interface KmsWrapResult {
  wrappedDek: string;
  keyRef: string;
  combinedRef: string;
}

export type KmsProviderType = 'local' | 'hsm-pkcs11' | 'vault' | 'aws-kms';

export abstract class KmsService {
  abstract wrapKey(plaintextDek: Buffer, aad?: Buffer | string): Promise<KmsWrapResult>;
  abstract unwrapKey(wrappedDek: string, keyRef: string, aad?: Buffer | string): Promise<Buffer>;
  abstract unwrapCombinedRef(combinedRef: string, aad?: Buffer | string): Promise<Buffer>;
}

/**
 * Thuật toán: Tách tham chiếu khóa kết hợp tại ký tự phân cách `:` bên phải ngoài cùng (`lastIndexOf(':')`).
 */
export function splitCombinedKeyRef(combinedRef: string): { keyRef: string; wrappedDek: string } {
  const colonIndex = combinedRef.lastIndexOf(':');
  if (colonIndex <= 0) {
    throw new Error('Invalid combined encryption key reference format.');
  }
  return {
    keyRef: combinedRef.substring(0, colonIndex),
    wrappedDek: combinedRef.substring(colonIndex + 1),
  };
}
