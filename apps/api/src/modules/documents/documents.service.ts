import { Injectable } from '@nestjs/common';

@Injectable()
export class DocumentsService {
  listDocuments(): { data: unknown[] } {
    return { data: [] };
  }

  getDocumentById(id: string): { id: string } {
    return { id };
  }
}
