import { Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient, type session_status } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type TransactionClient = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

export interface TerminateResult {
  count: number;
  affectedUserIds: bigint[];
}

export interface AccessSessionDto {
  id: string;
  accessGrantId: string;
  documentVersionId: number;
  userId: number;
  username: string;
  fullName: string;
  documentId: string;
  documentCode: string;
  documentTitle: string;
  versionNo: number;
  ipAddress: string;
  userAgent: string | null;
  status: string;
  startedAt: string;
  lastActivityAt: string;
  endedAt: string | null;
  terminatedReason: string | null;
}

@Injectable()
export class AccessSessionsService {
  private readonly logger = new Logger(AccessSessionsService.name);
  private readonly database: PrismaClient;

  constructor(@Optional() databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  async listSessions(options?: {
    status?: session_status;
    limit?: number;
  }): Promise<{ data: AccessSessionDto[] }> {
    const status = options?.status ?? 'ACTIVE';
    const limit = Math.min(options?.limit ?? 50, 100);

    const where: { status?: session_status } = {};
    if (status) {
      where.status = status;
    }

    const sessions = await this.database.accessSession.findMany({
      where,
      take: limit,
      orderBy: { started_at: 'desc' },
      include: {
        users: { select: { id: true, username: true, full_name: true } },
        document_versions: {
          select: {
            id: true,
            version_no: true,
            document: { select: { id: true, document_code: true, title: true } },
          },
        },
      },
    });

    const data: AccessSessionDto[] = sessions.map((s) => ({
      id: s.id,
      accessGrantId: s.access_grant_id,
      documentVersionId: Number(s.document_version_id),
      userId: Number(s.user_id),
      username: s.users.username,
      fullName: s.users.full_name,
      documentId: s.document_versions.document.id,
      documentCode: s.document_versions.document.document_code,
      documentTitle: s.document_versions.document.title,
      versionNo: s.document_versions.version_no,
      ipAddress: s.ip_address,
      userAgent: s.user_agent,
      status: s.status,
      startedAt: s.started_at.toISOString(),
      lastActivityAt: s.last_activity_at.toISOString(),
      endedAt: s.ended_at?.toISOString() ?? null,
      terminatedReason: s.terminated_reason,
    }));

    return { data };
  }

  async terminateSession(
    id: string,
    reason = 'Terminated by security officer',
  ): Promise<{ id: string; status: string }> {
    const session = await this.database.accessSession.findUnique({
      where: { id },
    });

    if (!session) {
      throw new NotFoundException(`Session ${id} not found.`);
    }

    if (session.status !== 'ACTIVE') {
      return { id: session.id, status: session.status };
    }

    const updated = await this.database.accessSession.update({
      where: { id },
      data: {
        status: 'TERMINATED',
        ended_at: new Date(),
        terminated_reason: reason,
      },
    });

    this.logger.warn(`Access session ${id} terminated manually. Reason: ${reason}`);

    return { id: updated.id, status: updated.status };
  }

  /**
   * Terminate all ACTIVE sessions associated with a specific grant.
   * Used during grant revocation and expiry.
   *
   * Can operate within a provided transaction or create its own.
   */
  async terminateSessionsByGrant(
    grantId: string,
    reason: string,
    now: Date = new Date(),
    tx?: TransactionClient,
  ): Promise<TerminateResult> {
    const execute = async (client: TransactionClient | PrismaClient): Promise<TerminateResult> => {
      // Find affected sessions first to collect user IDs
      const activeSessions = await client.accessSession.findMany({
        where: {
          access_grant_id: grantId,
          status: 'ACTIVE',
        },
        select: { id: true, user_id: true },
      });

      if (activeSessions.length === 0) {
        return { count: 0, affectedUserIds: [] };
      }

      const result = await client.accessSession.updateMany({
        where: {
          access_grant_id: grantId,
          status: 'ACTIVE',
        },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: reason,
        },
      });

      const uniqueUserIds = [...new Set(activeSessions.map((s) => s.user_id))];

      this.logger.log(`Terminated ${result.count} sessions for grant ${grantId}: ${reason}`);

      return {
        count: result.count,
        affectedUserIds: uniqueUserIds,
      };
    };

    if (tx) {
      return execute(tx);
    }
    return execute(this.database);
  }

  /**
   * Terminate all ACTIVE sessions for a specific user.
   * Used when user account is disabled or clearance changes.
   */
  async terminateSessionsByUser(
    userId: bigint,
    reason: string,
    now: Date = new Date(),
    tx?: TransactionClient,
  ): Promise<number> {
    const execute = async (client: TransactionClient | PrismaClient): Promise<number> => {
      const result = await client.accessSession.updateMany({
        where: {
          user_id: userId,
          status: 'ACTIVE',
        },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: reason,
        },
      });
      return result.count;
    };

    if (tx) {
      return execute(tx);
    }
    return execute(this.database);
  }

  /**
   * Terminate all ACTIVE sessions for a batch of grant IDs.
   * Used by the expiry worker.
   */
  async terminateSessionsByGrants(
    grantIds: string[],
    reason: string,
    now: Date = new Date(),
    tx?: TransactionClient,
  ): Promise<TerminateResult> {
    const execute = async (client: TransactionClient | PrismaClient): Promise<TerminateResult> => {
      const activeSessions = await client.accessSession.findMany({
        where: {
          access_grant_id: { in: grantIds },
          status: 'ACTIVE',
        },
        select: { user_id: true },
      });

      if (activeSessions.length === 0) {
        return { count: 0, affectedUserIds: [] };
      }

      const result = await client.accessSession.updateMany({
        where: {
          access_grant_id: { in: grantIds },
          status: 'ACTIVE',
        },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: reason,
        },
      });

      const uniqueUserIds = [...new Set(activeSessions.map((s) => s.user_id))];
      return { count: result.count, affectedUserIds: uniqueUserIds };
    };

    if (tx) {
      return execute(tx);
    }
    return execute(this.database);
  }
}
