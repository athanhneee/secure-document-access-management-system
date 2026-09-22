import { Injectable } from '@nestjs/common';

@Injectable()
export class AccessSessionsService {
  listSessions(): { data: unknown[] } {
    return { data: [] };
  }

  terminateSession(id: string): { id: string; status: string } {
    return { id, status: 'TERMINATED' };
  }
}
