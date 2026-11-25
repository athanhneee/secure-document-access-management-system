export const MFA_REQUIRED_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']);

export interface AuthUserProfile {
  id: string;
  username: string;
  email: string;
  fullName: string;
  departmentId: string | null;
  departmentName: string | null;
  clearanceOptionId: string | null;
  clearanceCode: string | null;
  clearanceName: string | null;
  clearanceRank: number;
  status: string;
  version: number;
  roles: string[];
  permissions: string[];
}

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
  requiresMfa?: boolean | undefined;
  profile?: AuthUserProfile | undefined;
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
  mfaPending?: boolean | undefined;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthPrincipal;
  }
}
