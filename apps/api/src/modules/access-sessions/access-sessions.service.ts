import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type TransactionClient = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

export interface TerminateResult {
  count: number;
  affectedUserIds: bigint[];
}

@Injectable()
export class AccessSessionsService {
  private readonly logger = new Logger(AccessSessionsService.name);
  private readonly database = getDatabaseClient();

  listSessions(): { data: unknown[] } {
    return { data: [] };
  }

  terminateSession(id: string): { id: string; status: string } {
    return { id, status: 'TERMINATED' };
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
