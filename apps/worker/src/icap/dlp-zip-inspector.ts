import { promisify } from 'node:util';
import { inflateRaw } from 'node:zlib';
import { extractPdfUtf16BeHexSurfaces, extractUtf16Surfaces } from './dlp-decoders.js';
import { isMaxOutputExceededError, MAX_DLP_DECOMPRESSED_BYTES } from './icap-content-decoder.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ bóc tách không phụ thuộc ngoài cho kho lưu trữ ZIP / OOXML (`.docx`, `.xlsx`, `.pptx`) và kho `.zip` đa tầng thư mục phục vụ DLP biên mạng:
 * - Kiểm tra cờ mã hóa mật khẩu truyền thống PKWARE (`flag & 0x0001`), Strong Encryption (`flag & 0x0040`) và WinZip AES (`method === 99`)
 *   trên **mọi** entry trước khi lọc đuôi tệp để chặn Fail-Closed tệp nén đặt mật khẩu ở bất kỳ định dạng nào.
 * - Nâng giới hạn duyệt entry lên `1000` (vượt trần ở chế độ quét đầy đủ -> chặn Fail-Closed), sắp xếp độ ưu tiên quét
 *   `word/document.xml`, `xl/sharedStrings.xml`, `xl/worksheets/*`, `ppt/slides/*` lên đầu và mở rộng quét `.pdf`, `.csv`, `.json`, `.txt`, `.xml` ở mọi thư mục con
 *   mà KHÔNG chặn nhầm các tệp media/nhị phân hợp lệ không mã hóa (`word/media/image1.png`, `.rels`, ...).
 */

const inflateRawAsync = promisify(inflateRaw);
export const MAX_ZIP_ENTRIES_INSPECTED = 1000;

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
  priority: number;
  originalIndex: number;
}

interface ParsedZipArchive {
  entries: ZipEntryDescriptor[];
  encryptedEntryDetected: boolean;
  entryLimitExceeded: boolean;
}

const XML_LIKE_EXTENSIONS = ['.xml', '.rels', '.html', '.htm', '.xhtml', '.svg'] as const;
const TEXT_AND_DATA_EXTENSIONS = [
  '.txt',
  '.csv',
  '.tsv',
  '.json',
  '.jsonl',
  '.ndjson',
  '.md',
  '.yaml',
  '.yml',
  '.ini',
  '.cfg',
  '.conf',
  '.env',
  '.log',
  '.sql',
  '.rtf',
] as const;

function isEncryptedZipEntry(generalPurposeFlag: number, compressionMethod: number): boolean {
  return (
    (generalPurposeFlag & 0x0001) !== 0 ||
    (generalPurposeFlag & 0x0040) !== 0 ||
    compressionMethod === 99
  );
}

function isXmlLikeEntryName(lowerName: string): boolean {
  return XML_LIKE_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
}

function isInspectableArchiveEntry(fileName: string): boolean {
  const normalized = fileName.replace(/\\/gu, '/').toLowerCase();
  if (!normalized || normalized.endsWith('/')) return false;
  if (normalized.endsWith('.pdf')) return true;
  if (isXmlLikeEntryName(normalized)) return true;
  return TEXT_AND_DATA_EXTENSIONS.some((ext) => normalized.endsWith(ext));
}

function getZipEntryPriority(fileName: string): number {
  const lower = fileName.replace(/\\/gu, '/').toLowerCase();
  if (lower === 'word/document.xml' || lower === 'xl/sharedstrings.xml') return 0;
  if (lower.startsWith('xl/worksheets/') || lower.startsWith('ppt/slides/')) return 1;
  if (
    lower.startsWith('word/header') ||
    lower.startsWith('word/footer') ||
    lower === 'word/footnotes.xml' ||
    lower === 'word/endnotes.xml' ||
    lower.startsWith('word/comments') ||
    lower.startsWith('ppt/notesslides/') ||
    lower.startsWith('xl/comments')
  ) {
    return 2;
  }
  if (
    lower.endsWith('.pdf') ||
    lower.endsWith('.csv') ||
    lower.endsWith('.tsv') ||
    lower.endsWith('.json') ||
    lower.endsWith('.jsonl') ||
    lower.endsWith('.txt') ||
    lower.endsWith('.md')
  ) {
    return 3;
  }
  if (
    lower.startsWith('word/') ||
    lower.startsWith('xl/') ||
    lower.startsWith('ppt/') ||
    lower.startsWith('docprops/') ||
    lower.startsWith('customxml/')
  ) {
    return 4;
  }
  return 5;
}

function safeCodePointToChar(cp: number): string {
  if (Number.isInteger(cp) && cp >= 1 && cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff)) {
    return String.fromCodePoint(cp);
  }
  return '\uFFFD';
}

export function decodeXmlEntities(text: string): string {
  return text
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"')
    .replace(/&apos;/gu, "'")
    .replace(/&#[xX]0*([0-9a-fA-F]{1,8});/gu, (_m, hex: string) =>
      safeCodePointToChar(Number.parseInt(hex, 16)),
    )
    .replace(/&#0*(\d{1,8});/gu, (_m, dec: string) => safeCodePointToChar(Number.parseInt(dec, 10)))
    .replace(/&amp;/gu, '&');
}

/**
 * Thuật toán: Phẳng hóa cây XML OOXML giữ nguyên tính liên tục của từ khóa bị chia nhỏ qua nhiều thẻ `<w:r><w:t>`.
 */
export function normalizeOoxmlXmlToPlainTexts(rawXml: string): string[] {
  const withBlockBreaks = rawXml.replace(/<\/(?:w:p|p|si|row|tr|t:p)>/giu, '\n');
  const joinedRuns = decodeXmlEntities(withBlockBreaks.replace(/<[^>]+>/gu, ''));
  const spacedRuns = decodeXmlEntities(rawXml.replace(/<[^>]+>/gu, ' '));
  return [joinedRuns, spacedRuns];
}

function extractEntryTexts(fileName: string, contentBuf: Buffer): string[] {
  const lower = fileName.replace(/\\/gu, '/').toLowerCase();
  const utf8Text = contentBuf.toString('utf8');
  const utf16Texts = extractUtf16Surfaces(contentBuf);

  if (lower.endsWith('.pdf')) {
    return [utf8Text, ...extractPdfUtf16BeHexSurfaces(utf8Text), ...utf16Texts];
  }

  if (isXmlLikeEntryName(lower)) {
    const out = [...normalizeOoxmlXmlToPlainTexts(utf8Text)];
    for (const u16 of utf16Texts) {
      out.push(...normalizeOoxmlXmlToPlainTexts(u16));
    }
    return out;
  }

  return [utf8Text, ...utf16Texts];
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
 * Thuật toán: Thu thập danh mục entry ZIP từ Central Directory hoặc quét tuần tự Local File Header `PK\x03\x04`,
 * kiểm tra cờ mã hóa trên MỌI entry trước khi lọc đuôi tệp và sắp xếp theo độ ưu tiên nội dung.
 */
function parseZipArchive(buf: Buffer): ParsedZipArchive {
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    return { entries: [], encryptedEntryDetected: false, entryLimitExceeded: false };
  }

  const entries: ZipEntryDescriptor[] = [];
  const eocdOffset = locateEocdOffset(buf);

  if (eocdOffset !== -1) {
    const totalEntries = buf.readUInt16LE(eocdOffset + 10);
    const entryLimitExceeded = totalEntries > MAX_ZIP_ENTRIES_INSPECTED;
    let cdOffset = buf.readUInt32LE(eocdOffset + 16);
    let parsedCdRecords = 0;

    for (let i = 0; i < totalEntries && cdOffset + 46 <= buf.length; i++) {
      if (buf.readUInt32LE(cdOffset) !== 0x02014b50) break;
      parsedCdRecords++;
      const generalPurposeFlag = buf.readUInt16LE(cdOffset + 8);
      const compressionMethod = buf.readUInt16LE(cdOffset + 10);
      const compressedSize = buf.readUInt32LE(cdOffset + 20);
      const uncompressedSize = buf.readUInt32LE(cdOffset + 24);
      const fileNameLen = buf.readUInt16LE(cdOffset + 28);
      const extraLen = buf.readUInt16LE(cdOffset + 30);
      const commentLen = buf.readUInt16LE(cdOffset + 32);
      const localHdrOffset = buf.readUInt32LE(cdOffset + 42);

      // Check password / WinZip AES encryption on EVERY entry before filtering by file extension!
      if (isEncryptedZipEntry(generalPurposeFlag, compressionMethod)) {
        return { entries, encryptedEntryDetected: true, entryLimitExceeded };
      }
      if (localHdrOffset + 30 <= buf.length && buf.readUInt32LE(localHdrOffset) === 0x04034b50) {
        const localFlag = buf.readUInt16LE(localHdrOffset + 6);
        const localMethod = buf.readUInt16LE(localHdrOffset + 8);
        if (isEncryptedZipEntry(localFlag, localMethod)) {
          return { entries, encryptedEntryDetected: true, entryLimitExceeded };
        }
      }

      if (cdOffset + 46 + fileNameLen > buf.length) break;

      if (parsedCdRecords <= MAX_ZIP_ENTRIES_INSPECTED) {
        const fileName = buf.subarray(cdOffset + 46, cdOffset + 46 + fileNameLen).toString('utf8');
        if (
          isInspectableArchiveEntry(fileName) &&
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
            priority: getZipEntryPriority(fileName),
            originalIndex: entries.length,
          });
        }
      } else if (parsedCdRecords > MAX_ZIP_ENTRIES_INSPECTED + 4096) {
        break;
      }

      cdOffset += 46 + fileNameLen + extraLen + commentLen;
    }

    if (parsedCdRecords > 0) {
      entries.sort((a, b) => a.priority - b.priority || a.originalIndex - b.originalIndex);
      return { entries, encryptedEntryDetected: false, entryLimitExceeded };
    }
  }

  let offset = 0;
  let totalLocalEntries = 0;
  let entryLimitExceeded = false;
  while (offset + 30 <= buf.length) {
    if (buf.readUInt32LE(offset) !== 0x04034b50) break;
    totalLocalEntries++;
    if (totalLocalEntries > MAX_ZIP_ENTRIES_INSPECTED) {
      entryLimitExceeded = true;
    }
    const generalPurposeFlag = buf.readUInt16LE(offset + 6);
    const compressionMethod = buf.readUInt16LE(offset + 8);
    if (isEncryptedZipEntry(generalPurposeFlag, compressionMethod)) {
      return { entries, encryptedEntryDetected: true, entryLimitExceeded };
    }

    const compressedSize = buf.readUInt32LE(offset + 18);
    const uncompressedSize = buf.readUInt32LE(offset + 22);
    const fileNameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);
    const dataStartOffset = offset + 30 + fileNameLen + extraLen;
    if (dataStartOffset > buf.length) break;

    if (totalLocalEntries <= MAX_ZIP_ENTRIES_INSPECTED) {
      const fileName = buf.subarray(offset + 30, offset + 30 + fileNameLen).toString('utf8');
      if (isInspectableArchiveEntry(fileName)) {
        entries.push({
          fileName,
          compressionMethod,
          generalPurposeFlag,
          compressedSize,
          uncompressedSize,
          dataStartOffset,
          priority: getZipEntryPriority(fileName),
          originalIndex: entries.length,
        });
      }
    } else if (totalLocalEntries > MAX_ZIP_ENTRIES_INSPECTED + 4096) {
      break;
    }

    if (compressedSize === 0 && (generalPurposeFlag & 0x0008) !== 0) break;
    offset = dataStartOffset + compressedSize;
  }

  entries.sort((a, b) => a.priority - b.priority || a.originalIndex - b.originalIndex);
  return { entries, encryptedEntryDetected: false, entryLimitExceeded };
}

/**
 * Thuật toán: Trích xuất đồng bộ các mục văn bản/XML không nén (`STORE`) phục vụ đường gọi đồng bộ `DlpEngine.scanPayload`.
 */
export function extractUncompressedZipXmlTextsSync(
  buf: Buffer,
  maxBytes = MAX_DLP_DECOMPRESSED_BYTES,
): ZipInspectionResult {
  const parsed = parseZipArchive(buf);
  if (parsed.encryptedEntryDetected) {
    return { texts: [], bombDetected: false, archiveError: 'ENCRYPTED_ARCHIVE_ENTRY' };
  }
  if (parsed.entryLimitExceeded) {
    return { texts: [], bombDetected: true, archiveError: 'ZIP_ENTRY_LIMIT_EXCEEDED' };
  }
  if (parsed.entries.length === 0) return { texts: [], bombDetected: false };

  const texts: string[] = [];
  let budget = maxBytes;

  for (const entry of parsed.entries) {
    if (isEncryptedZipEntry(entry.generalPurposeFlag, entry.compressionMethod)) {
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
      if (budget < 0) return { texts, bombDetected: true };
      texts.push(...extractEntryTexts(entry.fileName, slice));
    }
  }
  return { texts, bombDetected: false };
}

/**
 * Thuật toán: Trích xuất bất đồng bộ cả mục không nén (`STORE`) lẫn nén `DEFLATE` bên trong `.docx`/`.xlsx`/`.pptx`/`.zip`
 * có kiểm soát trần tổng dung lượng giải nén + trần số lượng entry chống Zip Bomb và Fail-Closed với kho mã hóa/hỏng.
 */
export async function extractZipXmlTextsAsync(
  buf: Buffer,
  maxBytes = MAX_DLP_DECOMPRESSED_BYTES,
  allowTruncatedPreview = false,
): Promise<ZipInspectionResult> {
  if (buf.length < 4 || buf.readUInt32LE(0) !== 0x04034b50) {
    return { texts: [], bombDetected: false };
  }
  const parsed = parseZipArchive(buf);
  if (parsed.encryptedEntryDetected) {
    return { texts: [], bombDetected: false, archiveError: 'ENCRYPTED_ZIP_ENTRY' };
  }
  if (parsed.entryLimitExceeded && !allowTruncatedPreview) {
    return { texts: [], bombDetected: true, archiveError: 'ZIP_ENTRY_LIMIT_EXCEEDED' };
  }

  const texts: string[] = [];
  let remainingBudget = maxBytes;

  for (const entry of parsed.entries) {
    if (isEncryptedZipEntry(entry.generalPurposeFlag, entry.compressionMethod)) {
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
      texts.push(...extractEntryTexts(entry.fileName, rawSlice));
    } else if (entry.compressionMethod === 8) {
      let inflated: Buffer | undefined;
      try {
        inflated = await inflateRawAsync(rawSlice, { maxOutputLength: remainingBudget });
      } catch (err) {
        if (isMaxOutputExceededError(err)) {
          return { texts, bombDetected: true };
        }
        if (!allowTruncatedPreview) {
          return { texts, bombDetected: false, archiveError: 'CORRUPT_OOXML_DEFLATE_STREAM' };
        }
      }
      if (inflated !== undefined) {
        remainingBudget -= inflated.length;
        texts.push(...extractEntryTexts(entry.fileName, inflated));
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
