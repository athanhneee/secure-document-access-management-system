import { Injectable } from '@nestjs/common';

@Injectable()
export class AccessGrantsService {
  listGrants(): { data: unknown[] } {
    return { data: [] };
  }

  revokeGrant(id: string): { id: string; status: string } {
    return { id, status: 'REVOKED' };
  }
}
