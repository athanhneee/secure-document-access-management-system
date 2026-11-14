/**
 * @module WindowsDefenderScannerHelper
 * Thuật toán: Quét mã độc dự phòng cục bộ trên Windows qua Microsoft Defender CLI (`MpCmdRun.exe`) khi container `clamd` không bật.
 *   1. Chỉ kích hoạt trên `process.platform === 'win32'` ở môi trường `development` khi `MpCmdRun.exe` tồn tại tại đường dẫn hệ thống chuẩn.
 *   2. Ghi payload nhị phân ra tệp tạm cô lập (`0o600`) trong `os.tmpdir()`, gọi `execFile` không qua shell (`-Scan -ScanType 3 -File <path> -DisableRemediation`) với thời hạn cứng `8_000ms`.
 *   3. Mã thoát `0` kết luận `CLEAN`, mã thoát `2` trích xuất tên mối đe dọa kết luận `INFECTED`; luôn xóa triệt để tệp tạm trong khối `finally`.
 */
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const WINDOWS_DEFENDER_CLI = 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe';
const DEFENDER_TIMEOUT_MS = 8_000;

export interface HostDefenderScanOutcome {
  executed: boolean;
  status: 'CLEAN' | 'INFECTED';
  virusName?: string;
}

/**
 * Thuật toán: Kiểm tra khả dụng trình quét Microsoft Defender bản địa trên hệ điều hành Windows.
 */
export function isWindowsDefenderCliAvailable(): boolean {
  if (process.platform !== 'win32') return false;
  if (process.env['SDA_DISABLE_HOST_DEFENDER'] === 'true') return false;
  if (
    process.env['NODE_TEST_CONTEXT'] &&
    process.env['SDA_ENABLE_DEV_FALLBACK_IN_TEST'] !== 'true'
  ) {
    return false;
  }
  try {
    return fs.existsSync(WINDOWS_DEFENDER_CLI);
  } catch {
    return false;
  }
}

function parseDefenderThreatName(stdout: string): string {
  const threatMatch = /Threat\s*:\s*([^\r\n]+)/iu.exec(stdout);
  if (threatMatch?.[1]) {
    return threatMatch[1].trim();
  }
  return 'Win32.Defender.DetectedThreat';
}

/**
 * Thuật toán: Thực thi quét tệp tùy chỉnh (`-ScanType 3`) qua `MpCmdRun.exe` không dùng shell và tự dọn tệp tạm.
 */
export async function scanBufferWithWindowsDefender(
  payload: Buffer,
): Promise<HostDefenderScanOutcome> {
  if (!isWindowsDefenderCliAvailable()) {
    return { executed: false, status: 'CLEAN' };
  }

  const tempFilePath = path.join(os.tmpdir(), `sda-av-${randomUUID()}.bin`);
  try {
    await fsp.writeFile(tempFilePath, payload, { mode: 0o600 });

    const outcome = await new Promise<HostDefenderScanOutcome>((resolve) => {
      execFile(
        WINDOWS_DEFENDER_CLI,
        ['-Scan', '-ScanType', '3', '-File', tempFilePath, '-DisableRemediation'],
        { timeout: DEFENDER_TIMEOUT_MS, windowsHide: true },
        (error, stdout) => {
          if (!error) {
            resolve({ executed: true, status: 'CLEAN' });
            return;
          }
          const rawCode = (error as { code?: number | string }).code;
          const outputText = typeof stdout === 'string' ? stdout : '';
          if (rawCode === 2 || rawCode === '2' || /found\s+\d+\s+threats/iu.test(outputText)) {
            resolve({
              executed: true,
              status: 'INFECTED',
              virusName: parseDefenderThreatName(outputText),
            });
            return;
          }
          resolve({ executed: false, status: 'CLEAN' });
        },
      );
    });

    return outcome;
  } catch {
    return { executed: false, status: 'CLEAN' };
  } finally {
    await fsp.unlink(tempFilePath).catch(() => {});
  }
}
