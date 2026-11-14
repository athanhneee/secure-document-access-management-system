/**
 * @module LocalLibreOfficeHelper
 * Thuật toán: Chuyển đổi tài liệu Office sang PDF qua tiến trình LibreOffice (`soffice`) bản địa không giao diện (`--headless`)
 * khi dịch vụ container Gotenberg không bật trên máy phát triển Windows/Linux.
 *   1. Quét danh sách đường dẫn nhị phân cố định tuyệt đối (chống tấn công chiếm quyền `PATH` hijacking) và chỉ chạy khi khác `NODE_ENV=test`.
 *   2. Ghi tài liệu nguồn vào thư mục tạm cô lập (`0o700`), thực thi `execFile` không qua shell với hồ sơ người dùng tạm riêng (`-env:UserInstallation=...`) và cắt thời hạn cứng.
 *   3. Kiểm chứng chữ ký ma thuật `%PDF` của tệp đầu ra và xóa sạch toàn bộ thư mục tạm trong `finally`.
 */
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const CANDIDATE_SOFFICE_BINARIES =
  process.platform === 'win32'
    ? [
        'C:\\Program Files\\LibreOffice\\program\\soffice.exe',
        'C:\\Program Files (x86)\\LibreOffice\\program\\soffice.exe',
      ]
    : [
        '/usr/bin/soffice',
        '/usr/local/bin/soffice',
        '/Applications/LibreOffice.app/Contents/MacOS/soffice',
      ];

function resolveLocalSofficeBinary(): string | null {
  if (process.env['NODE_ENV'] === 'test') return null;
  if (
    process.env['NODE_TEST_CONTEXT'] &&
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] !== 'true'
  ) {
    return null;
  }
  for (const candidate of CANDIDATE_SOFFICE_BINARIES) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // Bỏ qua đường dẫn không thể truy cập
    }
  }
  return null;
}

/**
 * Thuật toán: Kết xuất tài liệu Office sang PDF bằng `soffice --headless` trong thư mục tạm cô lập, trả `null` nếu máy chủ chưa cài LibreOffice.
 */
export async function convertWithLocalLibreOffice(
  officeBuffer: Buffer,
  filename: string,
  timeoutMs: number,
): Promise<Buffer | null> {
  const sofficeBin = resolveLocalSofficeBinary();
  if (!sofficeBin) return null;

  const ext = path.extname(filename).replace(/[^.a-zA-Z0-9]/gu, '') || '.docx';
  const workDir = path.join(os.tmpdir(), `sda-lo-${randomUUID()}`);
  const profileDir = path.join(workDir, 'profile');
  const inputPath = path.join(workDir, `source${ext}`);
  const outputPath = path.join(workDir, 'source.pdf');

  try {
    await fsp.mkdir(profileDir, { recursive: true, mode: 0o700 });
    await fsp.writeFile(inputPath, officeBuffer, { mode: 0o600 });

    const profileUrl = pathToFileURL(profileDir).href;
    const effectiveTimeout = Math.max(1_500, Math.min(timeoutMs, 8_000));

    const succeeded = await new Promise<boolean>((resolve) => {
      execFile(
        sofficeBin,
        [
          `-env:UserInstallation=${profileUrl}`,
          '--headless',
          '--nologo',
          '--nofirststartwizard',
          '--norestore',
          '--convert-to',
          'pdf',
          '--outdir',
          workDir,
          inputPath,
        ],
        { timeout: effectiveTimeout, windowsHide: true },
        (err) => resolve(!err),
      );
    });

    if (!succeeded || !fs.existsSync(outputPath)) {
      return null;
    }

    const pdfBuffer = await fsp.readFile(outputPath);
    if (pdfBuffer.length < 4 || pdfBuffer.subarray(0, 4).toString('ascii') !== '%PDF') {
      return null;
    }
    return pdfBuffer;
  } catch {
    return null;
  } finally {
    await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
