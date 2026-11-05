import http from 'node:http';
import { OfficeConverterService } from '../../dist/modules/documents/office-converter.service.js';

export async function withMockGotenbergServer(requestListener, runTest) {
  const server = http.createServer(requestListener);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const mockConfig = {
    get(key) {
      if (key === 'GOTENBERG_URL') return `http://127.0.0.1:${port}`;
      if (key === 'GOTENBERG_ENABLED') return true;
      return undefined;
    },
  };

  try {
    const converter = new OfficeConverterService(mockConfig);
    await runTest({ converter, mockConfig, port });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

export function createActivePepDocumentRow(docId, levelOverrides = {}, extraFields = {}) {
  return {
    id: docId,
    status: 'ACTIVE',
    department_id: 1n,
    owner_id: 10n,
    current_version: { id: 100n, version_no: 1, scan_status: 'CLEAN' },
    classification_history: [
      {
        classification_levels: {
          rank: 2,
          allow_download: true,
          require_watermark: true,
          ...levelOverrides,
        },
      },
    ],
    ...extraFields,
  };
}
