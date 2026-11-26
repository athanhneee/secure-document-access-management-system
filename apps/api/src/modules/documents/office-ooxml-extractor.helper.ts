/**
 * @module OfficeOoxmlExtractorHelper
 * Thuật toán: Trích xuất cấu trúc tài liệu Office OpenXML (`.docx`, `.xlsx`, `.pptx`) không rò handle `yauzl` (`BUG-059`):
 *   1. Lắng nghe cả sự kiện `'close'` kèm cờ `entryAdvanced` để khi `readStream.destroy()` trên mục XML `> 5 MiB` vẫn gọi `zipfile.readEntry()` và `zipfile.close()` tức thì (không treo 10s).
 *   2. `.xlsx`: Đọc `xl/sharedStrings.xml` kết hợp toàn bộ `xl/worksheets/sheet*.xml`.
 *   3. `.pptx`: Trích xuất toàn bộ trang chiếu `ppt/slides/slide*.xml` (không cắt 20 slide).
 */
import yauzl from 'yauzl';

const MAX_EXTRACT_BYTES = 5 * 1024 * 1024;

function decodeXmlEntities(raw: string): string {
  return raw
    .replace(/<[^>]+>/gu, '')
    .replace(/&amp;/gu, '&')
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"')
    .replace(/&apos;/gu, "'")
    .replace(/\s+/gu, ' ')
    .trim();
}

function extractEntriesMap(
  buffer: Buffer,
  matcher: (fileName: string) => boolean,
): Promise<Map<string, string>> {
  return new Promise((resolve) => {
    const results = new Map<string, string>();
    yauzl.fromBuffer(buffer, { lazyEntries: true, autoClose: false }, (err, zipfile) => {
      if (err || !zipfile) return resolve(results);
      let settled = false;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        try {
          zipfile.close();
        } catch {
          // Bỏ qua lỗi đóng luồng
        }
        resolve(results);
      };

      zipfile.readEntry();
      zipfile.on('entry', (entry) => {
        if (settled) return;
        if (!matcher(entry.fileName)) {
          zipfile.readEntry();
          return;
        }
        zipfile.openReadStream(entry, (streamErr, readStream) => {
          if (streamErr || !readStream) {
            zipfile.readEntry();
            return;
          }
          const chunks: Buffer[] = [];
          let total = 0;
          let entryAdvanced = false;
          const advanceEntry = (): void => {
            if (entryAdvanced || settled) return;
            entryAdvanced = true;
            zipfile.readEntry();
          };

          readStream.on('data', (c: Buffer) => {
            total += c.length;
            if (total <= MAX_EXTRACT_BYTES) {
              chunks.push(c);
            } else {
              readStream.destroy();
            }
          });
          readStream.on('end', () => {
            if (total <= MAX_EXTRACT_BYTES) {
              results.set(entry.fileName, Buffer.concat(chunks).toString('utf8'));
            }
            advanceEntry();
          });
          readStream.on('close', advanceEntry);
          readStream.on('error', advanceEntry);
        });
      });
      zipfile.on('end', finish);
      zipfile.on('error', finish);
    });
  });
}

function parseDocxStructuredText(xml: string): string {
  const blocks: string[] = [];
  const tokenRe = /<w:tbl\b[\s\S]*?<\/w:tbl>|<w:p\b[\s\S]*?<\/w:p>/gu;
  for (const match of xml.matchAll(tokenRe)) {
    const token = match[0];
    if (token.startsWith('<w:tbl')) {
      const rows = token.match(/<w:tr\b[\s\S]*?<\/w:tr>/gu) ?? [];
      for (const rowXml of rows) {
        const cells = (rowXml.match(/<w:tc\b[\s\S]*?<\/w:tc>/gu) ?? []).map((cellXml) =>
          decodeXmlEntities(cellXml.replace(/<\/w:p>/gu, ' ')),
        );
        if (cells.some((c) => c.length > 0)) {
          blocks.push(`| ${cells.join(' | ')} |`);
        }
      }
    } else {
      const line = decodeXmlEntities(token.replace(/<\/w:r>/gu, ' '));
      if (line.length > 0) blocks.push(line);
    }
  }
  return blocks.join('\n');
}

function parseWorksheetRows(sharedStrings: readonly string[], sheetXml: string): string[] {
  const lines: string[] = [];
  for (const rowMatch of sheetXml.matchAll(/<row\b[\s\S]*?<\/row>/gu)) {
    const cells: string[] = [];
    for (const cellMatch of rowMatch[0].matchAll(/<c\b([^>]*)>([\s\S]*?)<\/c>/gu)) {
      const attrs = cellMatch[1] ?? '';
      const inner = cellMatch[2] ?? '';
      const typeAttr = /\bt="([^"]+)"/u.exec(attrs)?.[1] ?? '';
      if (typeAttr === 'inlineStr') {
        cells.push(decodeXmlEntities(inner));
      } else {
        const rawVal = /<v\b[^>]*>([\s\S]*?)<\/v>/u.exec(inner)?.[1] ?? '';
        const cleanVal = decodeXmlEntities(rawVal);
        if (typeAttr === 's') {
          const idx = Number.parseInt(cleanVal, 10);
          cells.push(sharedStrings[idx] ?? cleanVal);
        } else {
          cells.push(cleanVal);
        }
      }
    }
    if (cells.some((c) => c.length > 0)) {
      lines.push(`| ${cells.join(' | ')} |`);
    }
  }
  return lines;
}

function parseXlsxStructuredText(
  sharedXml: string | undefined,
  sheetEntries: ReadonlyArray<readonly [string, string]>,
): string {
  const sharedStrings: string[] = [];
  if (sharedXml) {
    for (const si of sharedXml.matchAll(/<si\b[\s\S]*?<\/si>/gu)) {
      sharedStrings.push(decodeXmlEntities(si[0]));
    }
  }
  if (sheetEntries.length === 0) {
    return sharedStrings.length > 0
      ? sharedStrings.join('\n')
      : 'Workbook contains no printable cells.';
  }

  const sections: string[] = [];
  sheetEntries.forEach(([, sheetXml], index) => {
    const rows = parseWorksheetRows(sharedStrings, sheetXml);
    if (rows.length > 0) {
      if (sheetEntries.length > 1) {
        sections.push(`[Sheet ${index + 1}]`);
      }
      sections.push(...rows);
    }
  });

  return sections.length > 0 ? sections.join('\n') : sharedStrings.join('\n') || 'Empty worksheet.';
}

/**
 * Thuật toán: Trích xuất văn bản có cấu trúc bảng biểu từ gói nén Office OpenXML đã qua kiểm định an ninh.
 */
export async function extractOfficeFallbackText(
  officeBuffer: Buffer,
  filename: string,
): Promise<string> {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (ext === 'docx') {
    const entries = await extractEntriesMap(officeBuffer, (f) => f === 'word/document.xml');
    const xml = entries.get('word/document.xml');
    return xml
      ? parseDocxStructuredText(xml) || 'Document body is empty.'
      : 'Document body is empty.';
  }
  if (ext === 'xlsx') {
    const entries = await extractEntriesMap(
      officeBuffer,
      (f) => f === 'xl/sharedStrings.xml' || /^xl\/worksheets\/sheet\d+\.xml$/u.test(f),
    );
    const sortedSheets = [...entries.entries()]
      .filter(([name]) => /^xl\/worksheets\/sheet\d+\.xml$/u.test(name))
      .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }));
    return parseXlsxStructuredText(entries.get('xl/sharedStrings.xml'), sortedSheets);
  }
  if (ext === 'pptx') {
    const entries = await extractEntriesMap(officeBuffer, (f) =>
      /^ppt\/slides\/slide\d+\.xml$/u.test(f),
    );
    const sortedSlides = [...entries.entries()].sort((a, b) =>
      a[0].localeCompare(b[0], undefined, { numeric: true }),
    );
    const slidesText = sortedSlides
      .map(
        ([, xml], idx) => `[Slide ${idx + 1}] ${decodeXmlEntities(xml.replace(/<\/a:p>/gu, '\n'))}`,
      )
      .filter((s) => s.trim().length > 0);
    return slidesText.length > 0 ? slidesText.join('\n') : 'Presentation slide content.';
  }
  return `Document: ${filename}\nFormat: Office OpenXML`;
}
