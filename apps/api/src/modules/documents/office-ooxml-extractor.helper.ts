/**
 * @module OfficeOoxmlExtractorHelper
 * Thuật toán: Trích xuất cấu trúc tài liệu Office OpenXML (`.docx`, `.xlsx`, `.pptx`) phục vụ kết xuất PDF bảo toàn bảng biểu:
 *   1. `.docx`: Phân tích `<w:tbl>` -> `<w:tr>` -> `<w:tc>` thành dòng bảng `| Cột 1 | Cột 2 |` và đoạn văn `<w:p>`.
 *   2. `.xlsx`: Đọc bảng chuỗi dùng chung `xl/sharedStrings.xml` kết hợp lưới ô `<row><c>` của `xl/worksheets/sheet1.xml` (hỗ trợ cả `t="s"`, `t="inlineStr"` và giá trị số `<v>`).
 *   3. `.pptx`: Trích xuất tuần tự các trang chiếu `ppt/slides/slide1.xml`..`slide20.xml`.
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
          readStream.on('data', (c: Buffer) => {
            total += c.length;
            if (total <= MAX_EXTRACT_BYTES) chunks.push(c);
            else readStream.destroy();
          });
          readStream.on('end', () => {
            if (total <= MAX_EXTRACT_BYTES) {
              results.set(entry.fileName, Buffer.concat(chunks).toString('utf8'));
            }
            zipfile.readEntry();
          });
          readStream.on('error', () => zipfile.readEntry());
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

function parseXlsxStructuredText(
  sharedXml: string | undefined,
  sheetXml: string | undefined,
): string {
  const sharedStrings: string[] = [];
  if (sharedXml) {
    for (const si of sharedXml.matchAll(/<si\b[\s\S]*?<\/si>/gu)) {
      sharedStrings.push(decodeXmlEntities(si[0]));
    }
  }
  if (!sheetXml) {
    return sharedStrings.length > 0
      ? sharedStrings.join('\n')
      : 'Workbook contains no printable cells.';
  }

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
  return lines.length > 0 ? lines.join('\n') : sharedStrings.join('\n') || 'Empty worksheet.';
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
      (f) => f === 'xl/sharedStrings.xml' || f === 'xl/worksheets/sheet1.xml',
    );
    return parseXlsxStructuredText(
      entries.get('xl/sharedStrings.xml'),
      entries.get('xl/worksheets/sheet1.xml'),
    );
  }
  if (ext === 'pptx') {
    const entries = await extractEntriesMap(officeBuffer, (f) =>
      /^ppt\/slides\/slide\d+\.xml$/u.test(f),
    );
    const sortedSlides = [...entries.entries()].sort((a, b) =>
      a[0].localeCompare(b[0], undefined, { numeric: true }),
    );
    const slidesText = sortedSlides
      .slice(0, 20)
      .map(
        ([, xml], idx) => `[Slide ${idx + 1}] ${decodeXmlEntities(xml.replace(/<\/a:p>/gu, '\n'))}`,
      )
      .filter((s) => s.trim().length > 0);
    return slidesText.length > 0 ? slidesText.join('\n') : 'Presentation slide content.';
  }
  return `Document: ${filename}\nFormat: Office OpenXML`;
}
