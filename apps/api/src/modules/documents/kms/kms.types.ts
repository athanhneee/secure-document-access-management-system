/**
 * Module: Multi-Provider Envelope KMS Contracts & Combined Key Reference Parser
 * Algorithm: Defines the abstract `KmsService` envelope interface (`wrapKey`, `unwrapKey`, `unwrapCombinedRef`)
 *   and right-most delimiter parsing for `<provider>:<key-id>:<wrapped-dek>` references.
 */

export interface KmsWrapResult {
  wrappedDek: string;
  keyRef: string;
  combinedRef: string;
}

export type KmsProviderType = 'local' | 'hsm-pkcs11' | 'vault' | 'aws-kms';

export abstract class KmsService {
  abstract wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult>;
  abstract unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer>;
  abstract unwrapCombinedRef(combinedRef: string): Promise<Buffer>;
}

/**
 * Algorithm: Right-Most Delimiter Combined Key Reference Splitter
 * Splits `<provider-prefix>:<key-id>:<base64url-payload>` at the final `:` while preserving colons inside `keyRef`.
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
