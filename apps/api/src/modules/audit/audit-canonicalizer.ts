/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 *
 * Guarantees deterministic, reproducible JSON serialization across all runtimes
 * and environments. Essential for tamper-evident hash chaining and HMAC integrity verification.
 *
 * Rules:
 * 1. Lexicographical sorting of object keys based on UTF-16 code units.
 * 2. Standardized number representation (ECMAScript JSON.stringify matches RFC 8785).
 * 3. Compact whitespace (no spaces between tokens).
 * 4. Deep recursive canonicalization for objects and arrays.
 * 5. Undefined, function, and symbol object values are omitted.
 */

export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return JSON.stringify(value);
  }

  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString());
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  if (Array.isArray(value)) {
    const serializedElements = value.map((element) => {
      if (
        typeof element === 'undefined' ||
        typeof element === 'symbol' ||
        typeof element === 'function'
      ) {
        return 'null';
      }
      return canonicalizeJson(element);
    });
    return `[${serializedElements.join(',')}]`;
  }

  if (typeof value === 'object') {
    // If the object has a custom toJSON method, invoke it first
    if (typeof (value as { toJSON?: () => unknown }).toJSON === 'function') {
      return canonicalizeJson((value as { toJSON: () => unknown }).toJSON());
    }

    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const parts: string[] = [];

    for (const key of sortedKeys) {
      const val = obj[key];
      // Skip undefined, functions, and symbols in objects
      if (typeof val === 'undefined' || typeof val === 'symbol' || typeof val === 'function') {
        continue;
      }
      parts.push(`${JSON.stringify(key)}:${canonicalizeJson(val)}`);
    }

    return `{${parts.join(',')}}`;
  }

  return 'null';
}
