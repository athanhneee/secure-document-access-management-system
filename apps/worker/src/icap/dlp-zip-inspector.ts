import { promisify } from 'node:util';
import { inflateRaw } from 'node:zlib';
import { isMaxOutputExceededError, MAX_DLP_DECOMPRESSED_BYTES } from './icap-content-decoder.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ bóc tách không phụ thuộc ngoài cho kho lưu trữ ZIP / OOXML (`.docx`, `.xlsx`, `.pptx`) phục vụ DLP biên mạng:
 * - Ưu tiên đọc Central Directory (`0x06054b50` -> `0x02014b50`) và quay lui về Local File Header (`0x04034b50`) khi luồng bị cắt Preview.
 * - Giải nén bất đồng bộ `inflateRaw` có ngân sách tổng byte nghiêm ngặt chống Zip Bomb, đồng thời nối liền các thẻ chạy văn bản `<w:t>` / `<t>`
 *   trong `word/document.xml` và `xl/sharedStrings.xml` để bắt trọn mã watermark `WM-...` bị tách thẻ XML.
 */

const inflateRawAsync = promisify(inflateRaw);
const MAX_ZIP_ENTRIES_INSPECTED = 32;

export interface ZipInspectionResult {
  texts: string[];
  bombDetected: boolean;
  archiveError?: string;
}

interface ZipEntryDescriptor {
  fileName: string;
  compressionMethod: number;
  generalPurposeFlag: number;
  compressedSize: number;
  uncompressedSize: number;
  dataStartOffset: number;
}

function isInspectableOoxmlEntry(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  if (!lower.endsWith('.xml') && !lower.endsWith('.rels') && !lower.endsWith('.txt')) {
    return false;
  }
  return (
    lower === 'word/document.xml' ||
    lower === 'xl/sharedstrings.xml' ||
    lower.startsWith('word/') ||
    lower.startsWith('xl/') ||
    lower.startsWith('ppt/') ||
    lower.startsWith('docprops/') ||
    !lower.includes('/')
  );
}

function decodeXmlEntities(text: string): string {
  return text
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"')
    .replace(/&apos;/gu, "'")
    .replace(/&#x([0-9a-fA-F]{1,6});/gu, (_m, hex: string) =>
      String.fromCodePoint(parseInt(hex, 16) || 0x20),
    )
    .replace(/&#(\d{1,7});/gu, (_m, dec: string) => String.fromCodePoint(parseInt(dec, 10) || 0x20))
    .replace(/&amp;/gu, '&');
}

/**
 * Thuật toán: Phẳng hóa cây XML OOXML giữ nguyên tính liên tục của từ khóa bị chia nhỏ qua nhiều thẻ `<w:r><w:t>`.
 */
function normalizeOoxmlXmlToPlainTexts(rawXml: string): string[] {
  const withBlockBreaks = rawXml.replace(/<\/(?:w:p|p|si|row|tr|t:p)>/giu, '\n');
  const joinedRuns = decodeXmlEntities(withBlockBreaks.replace(/<[^>]+>/gu, ''));
  const spacedRuns = decodeXmlEntities(rawXml.replace(/<[^>]+>/gu, ' '));
  return [joinedRuns, spacedRuns];
}

function locateEocdOffset(buf: Buffer): number {
  const minPos = Math.max(0, buf.length - 65_557);
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      return i;
    }
  }
  return -1;
}

/**
 * Thuật toán: Thu thập danh mục entry ZIP từ Central Directory hoặc quét tuần tự Local File Header `PK\x03\x04`.
 */
function parseZipEntries(buf: Buffer): ZipEntryDescriptor[] {
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    return [];
  }

  const entries: ZipEntryDescriptor[] = [];
  const eocdOffset = locateEocdOffset(buf);

  if (eocdOffset !== -1) {
    const totalEntries = buf.readUInt16LE(eocdOffset + 10);
    let cdOffset = buf.readUInt32LE(eocdOffset + 16);
    for (
      let i = 0;
      i < totalEntries && cdOffset + 46 <= buf.length && entries.length < MAX_ZIP_ENTRIES_INSPECTED;
      i++
    ) {
      if (buf.readUInt32LE(cdOffset) !== 0x02014b50) break;
      const generalPurposeFlag = buf.readUInt16LE(cdOffset + 8);
      const compressionMethod = buf.readUInt16LE(cdOffset + 10);
      const compressedSize = buf.readUInt32LE(cdOffset + 20);
      const uncompressedSize = buf.readUInt32LE(cdOffset + 24);
      const fileNameLen = buf.readUInt16LE(cdOffset + 28);
      const extraLen = buf.readUInt16LE(cdOffset + 30);
      const commentLen = buf.readUInt16LE(cdOffset + 32);
      const localHdrOffset = buf.readUInt32LE(cdOffset + 42);
      if (cdOffset + 46 + fileNameLen > buf.length) break;

      const fileName = buf.subarray(cdOffset + 46, cdOffset + 46 + fileNameLen).toString('utf8');
      if (
        isInspectableOoxmlEntry(fileName) &&
        localHdrOffset + 30 <= buf.length &&
        buf.readUInt32LE(localHdrOffset) === 0x04034b50
      ) {
        const localNameLen = buf.readUInt16LE(localHdrOffset + 26);
        const localExtraLen = buf.readUInt16LE(localHdrOffset + 28);
        const dataStartOffset = localHdrOffset + 30 + localNameLen + localExtraLen;
        entries.push({
          fileName,
          compressionMethod,
          generalPurposeFlag,
          compressedSize,
          uncompressedSize,
          dataStartOffset,
        });
      }
      cdOffset += 46 + fileNameLen + extraLen + commentLen;
    }
    if (entries.length > 0) return entries;
  }

  let offset = 0;
  while (offset + 30 <= buf.length && entries.length < MAX_ZIP_ENTRIES_INSPECTED) {
    if (buf.readUInt32LE(offset) !== 0x04034b50) break;
    const generalPurposeFlag = buf.readUInt16LE(offset + 6);
    const compressionMethod = buf.readUInt16LE(offset + 8);
    const compressedSize = buf.readUInt32LE(offset + 18);
    const uncompressedSize = buf.readUInt32LE(offset + 22);
    const fileNameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);
    const dataStartOffset = offset + 30 + fileNameLen + extraLen;
    if (dataStartOffset > buf.length) break;

    const fileName = buf.subarray(offset + 30, offset + 30 + fileNameLen).toString('utf8');
    if (isInspectableOoxmlEntry(fileName)) {
      entries.push({
        fileName,
        compressionMethod,
        generalPurposeFlag,
        compressedSize,
        uncompressedSize,
        dataStartOffset,
      });
    }
    if (compressedSize === 0 && (generalPurposeFlag & 0x0008) !== 0) break;
    offset = dataStartOffset + compressedSize;
  }
  return entries;
}

/**
 * Thuật toán: Trích xuất đồng bộ các mục XML không nén (`STORE`) phục vụ đường gọi đồng bộ `DlpEngine.scanPayload`.
 */
export function extractUncompressedZipXmlTextsSync(
  buf: Buffer,
  maxBytes = MAX_DLP_DECOMPRESSED_BYTES,
): ZipInspectionResult {
  const entries = parseZipEntries(buf);
  if (entries.length === 0) return { texts: [], bombDetected: false };
  const texts: string[] = [];
  let budget = maxBytes;

  for (const entry of entries) {
    if ((entry.generalPurposeFlag & 0x0001) !== 0) {
      return { texts, bombDetected: false, archiveError: 'ENCRYPTED_ARCHIVE_ENTRY' };
    }
    if (entry.uncompressedSize > budget) {
      return { texts, bombDetected: true };
    }
    if (
      entry.compressionMethod === 0 &&
      entry.dataStartOffset + entry.compressedSize <= buf.length
    ) {
      const slice = buf.subarray(
        entry.dataStartOffset,
        entry.dataStartOffset + entry.compressedSize,
      );
      budget -= slice.length;
      texts.push(...normalizeOoxmlXmlToPlainTexts(slice.toString('utf8')));
    }
  }
  return { texts, bombDetected: false };
}

/**
 * Thuật toán: Trích xuất bất đồng bộ cả mục XML không nén (`STORE`) lẫn nén `DEFLATE` bên trong `.docx`/`.xlsx`
 * có kiểm soát trần tổng dung lượng giải nén chống Zip Bomb và Fail-Closed với kho mã hóa/hỏng.
 */
export async function extractZipXmlTextsAsync(
  buf: Buffer,
  maxBytes = MAX_DLP_DECOMPRESSED_BYTES,
  allowTruncatedPreview = false,
): Promise<ZipInspectionResult> {
  if (buf.length < 4 || buf.readUInt32LE(0) !== 0x04034b50) {
    return { texts: [], bombDetected: false };
  }
  const entries = parseZipEntries(buf);
  const texts: string[] = [];
  let remainingBudget = maxBytes;

  for (const entry of entries) {
    if ((entry.generalPurposeFlag & 0x0001) !== 0) {
      return { texts, bombDetected: false, archiveError: 'ENCRYPTED_ZIP_ENTRY' };
    }
    if (entry.uncompressedSize > remainingBudget) {
      return { texts, bombDetected: true };
    }
    const availableEnd = Math.min(buf.length, entry.dataStartOffset + entry.compressedSize);
    const rawSlice = buf.subarray(entry.dataStartOffset, availableEnd);

    if (entry.compressionMethod === 0) {
      remainingBudget -= rawSlice.length;
      if (remainingBudget < 0) return { texts, bombDetected: true };
      texts.push(...normalizeOoxmlXmlToPlainTexts(rawSlice.toString('utf8')));
    } else if (entry.compressionMethod === 8) {
      try {
        const inflated = await inflateRawAsync(rawSlice, { maxOutputLength: remainingBudget });
        remainingBudget -= inflated.length;
        texts.push(...normalizeOoxmlXmlToPlainTexts(inflated.toString('utf8')));
      } catch (err) {
        if (isMaxOutputExceededError(err)) {
          return { texts, bombDetected: true };
        }
        if (!allowTruncatedPreview) {
          return { texts, bombDetected: false, archiveError: 'CORRUPT_OOXML_DEFLATE_STREAM' };
        }
      }
    } else if (!allowTruncatedPreview) {
      return {
        texts,
        bombDetected: false,
        archiveError: `UNSUPPORTED_ZIP_METHOD:${entry.compressionMethod}`,
      };
    }
  }

  return { texts, bombDetected: false };
}
