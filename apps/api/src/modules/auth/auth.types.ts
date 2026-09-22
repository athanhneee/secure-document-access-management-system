export const MFA_REQUIRED_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']);

export interface AuthUser {
  id: bigint;
  username: string;
  email: string;
  passwordHash: string;
  fullName: string;
  status: 'PENDING' | 'ACTIVE' | 'LOCKED' | 'DISABLED';
  lockedUntil: Date | null;
  failedLoginCount: number;
  roles: string[];
  mfaMethod: {
    id: string;
    encryptedSecret: string;
    recoveryCodeHashes: string[];
  } | null;
}

export interface RequestContext {
  ip: string;
  userAgent?: string | undefined;
  correlationId: string;
}

export interface AuthPrincipal {
  userId: bigint;
  sessionId: string;
  username: string;
  roles: string[];
  mfa: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthPrincipal;
  }
}
