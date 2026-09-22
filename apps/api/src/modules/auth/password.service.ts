import { Injectable } from '@nestjs/common';
import argon2 from 'argon2';

export const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
});

const COMMON_PASSWORDS = new Set([
  '123456789',
  '12345678',
  'password',
  'password1',
  'qwerty123',
  'admin123',
  'letmein',
  'welcome',
  'welcome1',
  'iloveyou',
  'monkey',
  'dragon',
  'football',
  'abc123456',
  'changeme',
]);

@Injectable()
export class PasswordService {
  private dummyHashPromise?: Promise<string>;

  validate(password: string, accountIdentifiers: string[] = []): void {
    if (password.length < 15 || password.length > 128) {
      throw new Error('PASSWORD_LENGTH');
    }
    const normalized = password.normalize('NFKC').toLowerCase();
    if (COMMON_PASSWORDS.has(normalized)) throw new Error('PASSWORD_COMMON');
    if (
      accountIdentifiers.some((value) => {
        const candidate = value.normalize('NFKC').toLowerCase().split('@')[0] ?? '';
        return candidate.length >= 4 && normalized.includes(candidate);
      })
    ) {
      throw new Error('PASSWORD_CONTAINS_IDENTIFIER');
    }
  }

  hash(password: string): Promise<string> {
    return argon2.hash(password, ARGON2ID_OPTIONS);
  }

  async verify(storedHash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(storedHash, password);
    } catch {
      return false;
    }
  }

  async burnEquivalentWork(password: string): Promise<void> {
    this.dummyHashPromise ??= this.hash('non-account dummy password value');
    await this.verify(await this.dummyHashPromise, password);
  }
}
