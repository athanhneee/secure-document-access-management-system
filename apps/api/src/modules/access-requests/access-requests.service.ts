import { Injectable } from '@nestjs/common';

@Injectable()
export class AccessRequestsService {
  listRequests(): { data: unknown[] } {
    return { data: [] };
  }

  cancelRequest(id: string): { id: string; status: string } {
    return { id, status: 'CANCELLED' };
  }
}
