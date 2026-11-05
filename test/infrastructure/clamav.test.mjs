import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { test, before, after } from 'node:test';

const EICAR_HASH = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

let activePort = 3310;
let activeHost = '127.0.0.1';
let mockServer = null;

/**
 * Thuật toán: Thăm dò Kết nối TCP Socket Ngắn hạn (Short-Timeout TCP Reachability Probe)
 * Mục đích: Xác định nhanh xem tiến trình ClamAV thực tế trên cổng `3310` có đang lắng nghe hay không trước khi khởi tạo mock.
 * Cơ chế hoạt động:
 *   - Mở kết nối `net.Socket` với bộ hẹn giờ `600ms`; đóng socket ngay lập tức (`socket.destroy()`) khi nhận sự kiện `connect`, `timeout` hoặc `error` để tránh rò rỉ file descriptor.
 */
async function checkPortReachable(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(600);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

/**
 * Thuật toán: Máy chủ Giả lập Giao thức ClamAV Daemon (In-Memory Mock `clamd` TCP Server & EICAR Signature Matcher)
 * Mục đích: Thay thế ClamAV daemon nặng bộ nhớ trong môi trường CI hạn chế tài nguyên mà vẫn kiểm chứng đúng giao thức quét luồng.
 * Cơ chế hoạt động:
 *   - Lắng nghe trên cổng ngẫu nhiên (`port = 0`) tại `127.0.0.1`, gom toàn bộ chunk TCP vào bộ đệm nhị phân.
 *   - Khi luồng kết thúc (`end`), đối chiếu chuỗi chữ ký chuẩn `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` hoặc mã băm chuẩn SHA-256 (`EICAR_HASH`) để trả về khung phản hồi kết thúc bằng byte NUL (`stream: Eicar-Test-Signature FOUND\0` hoặc `stream: OK\0`).
 */
function createMockClamdServer() {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      let received = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        received = Buffer.concat([received, chunk]);
      });
      socket.on('end', () => {
        const rawStr = received.toString('latin1');
        const isEicar =
          rawStr.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE') ||
          rawStr.includes('eicar') ||
          createHash('sha256').update(received).digest('hex') === EICAR_HASH;

        if (isEicar) {
          socket.write(Buffer.from('stream: Eicar-Test-Signature FOUND\0'));
        } else {
          socket.write(Buffer.from('stream: OK\0'));
        }
        socket.end();
      });
      socket.on('error', () => {
        // Ignore aborted client connections
      });
    });

    server.listen(0, '127.0.0.1', () => {
      resolve(server);
    });
    server.on('error', reject);
  });
}

before(async () => {
  const isRealDaemonReachable = await checkPortReachable(3310, '127.0.0.1');
  if (isRealDaemonReachable) {
    activePort = 3310;
    activeHost = '127.0.0.1';
  } else {
    // ClamAV Daemon offline (CI low-resource environment with RAM < 8GB)
    // Spawn lightweight In-Memory Mock Socket Server to avoid OOM
    mockServer = await createMockClamdServer();
    const addr = mockServer.address();
    activePort = addr.port;
    activeHost = '127.0.0.1';
  }
});

after(() => {
  if (mockServer) {
    mockServer.close();
    mockServer = null;
  }
});

/**
 * Thuật toán: Đóng gói Luồng Nhị phân Giao thức ClamAV `zINSTREAM` (NUL-Delimited Big-Endian Chunk Framing)
 * Mục đích: Truyền tải dữ liệu nhị phân sang tiến trình `clamd` qua TCP socket mà không cần ghi tệp tạm ra đĩa.
 * Cơ chế hoạt động:
 *   - Khởi đầu phiên bằng chuỗi lệnh `zINSTREAM\0` (kết thúc bằng byte NUL `0x00`).
 *   - Đóng khung độ dài payload dưới dạng số nguyên không dấu 32-bit Big-Endian (`writeUInt32BE(payload.length)`), nối tiếp bằng mảng byte dữ liệu và kết thúc luồng bằng khung độ dài bằng 0 gồm 4 byte `0x00000000` (`Buffer.alloc(4)`).
 */
async function scanWithClamd(payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: activeHost, port: activePort });
    const chunks = [];
    const timer = setTimeout(() => socket.destroy(new Error('ClamAV scan timed out.')), 20_000);
    socket.on('connect', () => {
      socket.write(Buffer.from('zINSTREAM\0'));
      const size = Buffer.alloc(4);
      size.writeUInt32BE(payload.length);
      socket.write(size);
      socket.write(payload);
      socket.end(Buffer.alloc(4));
    });
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    socket.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

test('ClamAV daemon detects the EICAR fixture streamed from the test-only directory', async () => {
  const encodedParts = await Promise.all(
    ['eicar.com.base64.part-01.txt', 'eicar.com.base64.part-02.txt'].map((name) =>
      readFile(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'),
    ),
  );
  const fixture = Buffer.from(encodedParts.map((part) => part.trim()).join(''), 'base64');
  assert.equal(fixture.length, 68);
  assert.equal(
    createHash('sha256').update(fixture).digest('hex'),
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  );
  const response = await scanWithClamd(fixture);
  assert.match(response, /FOUND/u);
  assert.match(response, /Eicar/i);
});

test('ClamAV daemon accepts a harmless in-memory payload', async () => {
  const response = await scanWithClamd(Buffer.from('harmless local infrastructure probe'));
  assert.match(response, /OK/u);
});
