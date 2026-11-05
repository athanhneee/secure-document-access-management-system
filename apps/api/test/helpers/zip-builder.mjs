import zlib from 'node:zlib';
import { PDFDocument } from 'pdf-lib';

/**
 * Algorithm: PKZIP Deflate Archive Binary Encoder
 * Description: Constructs a standards-compliant PKZIP archive buffer in memory by raw-deflating
 *              each entry, computing IEEE 802.3 CRC-32 checksums, emitting 30-byte Local File
 *              Headers (`0x04034b50`) followed by compressed payloads, appending 46-byte Central
 *              Directory File Headers (`0x02014b50`) with relative byte offsets, and sealing with
 *              a 22-byte End of Central Directory Record (`0x06054b50`). Supports optional
 *              uncompressed-size header spoofing to test anti-zip-bomb stream guards.
 * Time Complexity: O(N + B) where N is the entry count and B is total uncompressed payload bytes.
 * Space Complexity: O(B) for buffered local headers, compressed streams, and central directory.
 */
/**
 * Thuật toán: Đóng gói Khung Nhị phân Lưu trữ PKZIP Nén Deflate (`createZipBuffer` — PKZIP APPNOTE & RFC 1951)
 * Mục đích: Khởi tạo bộ đệm tệp nén ZIP/OOXML hợp lệ ngay trong bộ nhớ RAM (kèm chế độ giả mạo kích thước giải nén `spoofUncompressedZero` để kiểm thử chống Zip Bomb).
 * Cơ chế hoạt động:
 *   - Với mỗi mục tệp (`entry`), tính mã kiểm dư chu trình IEEE 802.3 CRC-32 (đa thức đảo `0xEDB88320` qua `zlib.crc32`) trên luồng byte gốc chưa nén và nén tải trọng bằng thuật toán Raw Deflate RFC 1951 (`zlib.deflateRawSync`, phương thức nén `8`).
 *   - Dựng khung Local File Header dài 30 byte theo thứ tự Little-Endian với chữ ký `0x04034b50`, ghi phiên bản giải nén `20` (PKZIP 2.0), mã CRC-32, kích thước nén, kích thước khai báo và độ dài tên tệp, nối tiếp bởi tên tệp UTF-8 và luồng byte nén.
 *   - Dựng danh mục trung tâm Central Directory File Header dài 46 byte mỗi tệp (chữ ký `0x02014b50`) lưu độ dời tương đối `offset` trỏ về từng Local File Header.
 *   - Khép kín tệp nén bằng bản ghi End of Central Directory (EOCD) dài 22 byte Little-Endian (chữ ký `0x06054b50`) ghi tổng số mục tệp, kích thước và vị trí bắt đầu của Central Directory. Độ phức tạp thời gian và bộ nhớ `O(N + B)`.
 */
export function createZipBuffer(filesOrEntries, { spoofUncompressedZero = false } = {}) {
  const entries = Array.isArray(filesOrEntries)
    ? filesOrEntries
    : Object.entries(filesOrEntries).map(([name, content]) => ({ name, content }));

  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content, 'utf8');
    const crc = zlib.crc32(content);
    const declaredUncompressed = spoofUncompressedZero ? 1 : content.length;
    const compressedData = zlib.deflateRawSync(content);
    const compressedSize = compressedData.length;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(8, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(declaredUncompressed, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    localHeaders.push(lh, nameBuf, compressedData);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compressedSize, 20);
    ch.writeUInt32LE(declaredUncompressed, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);

    centralHeaders.push(ch, nameBuf);
    offset += 30 + nameBuf.length + compressedSize;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

/**
 * Thuật toán: Khởi tạo Khung Nhị phân Tệp PDF Tối giản (`%PDF-1.5` Magic Byte Stub)
 * Mục đích: Sinh nhanh bộ đệm mang chữ ký đầu `%PDF-1.5` và chân trang `%%EOF` phục vụ kiểm thử nhận diện magic bytes.
 * Cơ chế hoạt động:
 *   - Ghép tiêu đề chuẩn ISO 32000-1 `%PDF-1.5`, nội dung văn bản thử nghiệm và dấu kết thúc tệp `%%EOF` sang `Buffer` UTF-8.
 */
export function createSamplePdfBuffer(content = 'Confidential Government Memo') {
  return Buffer.from(`%PDF-1.5\n%Sample Document\n${content}\n%%EOF`);
}

/**
 * Thuật toán: Đóng gói Tài liệu Office OpenXML WordprocessingML Tối giản (`createSampleDocxBuffer` — ECMA-376)
 * Mục đích: Tạo tệp `.docx` hợp lệ cấu trúc ZIP chứa danh mục kiểu nội dung và thân tài liệu XML.
 * Cơ chế hoạt động:
 *   - Gọi `createZipBuffer` đóng gói hai thành phần bắt buộc `[Content_Types].xml` và `word/document.xml` để vượt qua bộ kiểm tra cấu trúc OOXML.
 */
export function createSampleDocxBuffer(content = 'Sensitive Project Plan') {
  return createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    {
      name: 'word/document.xml',
      content: `<?xml version="1.0"?><w:document>${content}</w:document>`,
    },
  ]);
}

/**
 * Thuật toán: Đóng gói Bảng tính Office OpenXML SpreadsheetML Tối giản (`createSampleXlsxBuffer` — ECMA-376)
 * Mục đích: Tạo tệp `.xlsx` hợp lệ cấu trúc ZIP phục vụ kiểm thử đường ống tiếp nhận và chuyển đổi tài liệu.
 * Cơ chế hoạt động:
 *   - Gọi `createZipBuffer` đóng gói `[Content_Types].xml` và `xl/workbook.xml`.
 */
export function createSampleXlsxBuffer() {
  return createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'xl/workbook.xml', content: '<?xml version="1.0"?><workbook></workbook>' },
  ]);
}

/**
 * Thuật toán: Dựng Cây Đối tượng Tài liệu PDF Đa trang Chuẩn A4 (`createSamplePdf`)
 * Mục đích: Sinh tệp PDF nhị phân nhiều trang hoàn chỉnh bảng tham chiếu chéo (`xref`) phục vụ kiểm thử đóng dấu thủy vân từng trang.
 * Cơ chế hoạt động:
 *   - Dùng `pdf-lib` khởi tạo `PDFDocument`, lặp thêm `pageCount` trang khổ chuẩn A4 (`595.28 x 841.89 pt`), vẽ dòng chữ định danh trang và tuần tự hóa ra `Buffer`.
 */
export async function createSamplePdf(pageCount = 3) {
  const doc = await PDFDocument.create();
  for (let i = 0; i < pageCount; i++) {
    const page = doc.addPage([595.28, 841.89]);
    page.drawText(`Confidential Internal Document - Page ${i + 1}`, {
      x: 50,
      y: 800,
      size: 16,
    });
  }
  const bytes = await doc.save();
  return Buffer.from(bytes);
}
