/**
 * Re-exports the single canonical RFC 8785 JCS serializer from `@sda/contracts`
 * to eliminate cross-package duplication while preserving existing module imports.
 */
export { canonicalizeJson } from '@sda/contracts';
