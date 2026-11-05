/**
 * Module: HealthService — Tổng hợp trạng thái sẵn sàng đa thành phần hạ tầng (PostgreSQL, Redis, S3/MinIO) và ảnh chụp sức khỏe vận hành.
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { LivenessResponse, ReadinessResponse } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import {
  probeDatabaseEndpoint,
  probeRedisEndpoint,
  probeStorageEndpoint,
} from './dependency-probes.helper.js';

@Injectable()
export class HealthService {
  constructor(
    private readonly configService: AppConfigService,
    @Optional() private readonly databaseClient?: ReturnType<typeof getDatabaseClient>,
  ) {}

  /**
   * Thuật toán: Kiểm tra sự sống tiến trình tức thời (Zero-Dependency Liveness Probe)
   * Mục đích: Xác nhận vòng lặp sự kiện Node.js của tiến trình API vẫn phản hồi mà không phụ thuộc vào kết nối hạ tầng bên ngoài.
   * Cơ chế hoạt động:
   *   - Trả về hằng trạng thái `{ status: 'ok' }` độ phức tạp `O(1)` để bộ điều phối container (Kubernetes/Docker) tránh khởi động lại dây chuyền khi CSDL bảo trì.
   */
  checkLiveness(): LivenessResponse {
    return { status: 'ok' };
  }

  /**
   * Thuật toán: Tổng hợp trạng thái sẵn sàng song song đa thành phần có giới hạn thời gian (Bounded-Timeout Parallel Readiness Aggregation)
   * Mục đích: Đánh giá đồng thời độ trễ và khả năng kết nối tới PostgreSQL, Redis và Object Storage trước khi nhận lưu lượng truy cập.
   * Cơ chế hoạt động:
   *   - Phát đồng thời 3 phép thử qua `Promise.all` với ngưỡng cắt `timeoutMs = 2000ms` (tổng thời gian chờ tối đa bằng nhánh chậm nhất thay vì cộng dồn tuần tự).
   *   - Áp dụng phép hội logic nghiêm ngặt `isReady = (db === 'up' && redis === 'up' && storage === 'up')`; nếu bất kỳ thành phần nào lỗi, hạ trạng thái tổng thể xuống `'degraded'`.
   *
   * Algorithm: Parallel Dependency Readiness Aggregation.
   * Executes PostgreSQL, Redis, and Object Storage probes concurrently under a 2s timeout
   * and marks overall status `ready` iff all three dependencies report `up`.
   */
  async checkReadiness(): Promise<{ isReady: boolean; response: ReadinessResponse }> {
    const timestamp = new Date().toISOString();
    const timeoutMs = 2_000;

    const [database, redis, storage] = await Promise.all([
      probeDatabaseEndpoint(this.configService, timeoutMs),
      probeRedisEndpoint(this.configService, timeoutMs),
      probeStorageEndpoint(this.configService, timeoutMs),
    ]);

    const isReady = database.status === 'up' && redis.status === 'up' && storage.status === 'up';

    const response: ReadinessResponse = {
      status: isReady ? 'ready' : 'degraded',
      timestamp,
      checks: {
        database,
        redis,
        storage,
      },
    };

    return { isReady, response };
  }

  /**
   * Thuật toán: Thu thập bức tranh vận hành thời gian thực chịu lỗi suy giảm (Degraded-Tolerant Operational Telemetry Snapshot)
   * Mục đích: Cung cấp thông số bộ nhớ tiến trình (Heap/RSS), số phiên hoạt động, cảnh báo mở và hàng đợi xuất báo cáo cho bảng điều khiển quản trị ngay cả khi CSDL gặp sự cố.
   * Cơ chế hoạt động:
   *   - Đọc thống kê bộ nhớ `process.memoryUsage()` quy đổi sang MiB làm tròn 2 chữ số thập phân.
   *   - Thực thi song song 3 truy vấn `count` (`accessSession`, `securityAlert`, `asyncExportJob`) bên trong khối `try/catch` suy giảm êm (graceful degradation về `0` khi CSDL gián đoạn) kết hợp kết quả `checkReadiness()`.
   *
   * Algorithm: Degraded-Tolerant Live Operational Telemetry Snapshot.
   * Combines Node.js heap/RSS statistics, live database operational counts (gracefully defaulting
   * to zero when DB is unreachable), and dependency readiness checks.
   */
  async getLiveMetrics() {
    const memory = process.memoryUsage();
    const uptimeSeconds = Math.floor(process.uptime());
    const db = this.getDb();

    let activeSessionsCount = 0;
    let openAlertsCount = 0;
    let pendingExportsCount = 0;

    if (db) {
      try {
        const [activeSessions, openAlerts, pendingExports] = await Promise.all([
          db.accessSession.count({ where: { status: 'ACTIVE' } }),
          db.securityAlert.count({ where: { status: { in: ['OPEN', 'INVESTIGATING'] } } }),
          db.asyncExportJob.count({ where: { status: 'PENDING' } }),
        ]);
        activeSessionsCount = activeSessions;
        openAlertsCount = openAlerts;
        pendingExportsCount = pendingExports;
      } catch {
        // Handle gracefully if database is in degraded state
      }
    }

    const { isReady, response } = await this.checkReadiness();

    return {
      timestamp: new Date().toISOString(),
      process: {
        uptimeSeconds,
        heapUsedMb: Math.round((memory.heapUsed / 1024 / 1024) * 100) / 100,
        heapTotalMb: Math.round((memory.heapTotal / 1024 / 1024) * 100) / 100,
        rssMb: Math.round((memory.rss / 1024 / 1024) * 100) / 100,
      },
      operational: {
        activeSessionsCount,
        openAlertsCount,
        pendingExportsCount,
      },
      dependencies: {
        isReady,
        checks: response.checks,
      },
    };
  }

  /**
   * Thuật toán: Ghi nhận ảnh chụp sức khỏe vận hành chuẩn hóa kiểu dữ liệu JSON-safe (BigInt-Free Snapshot Serialization).
   * Đảm bảo trạng thái thuộc tập `('HEALTHY', 'DEGRADED', 'DOWN')` và chuyển mọi trường `bigint`/`Date` sang chuỗi trước khi trả về.
   */
  async captureBusinessSnapshot(
    serviceName: string,
    status: 'HEALTHY' | 'DEGRADED' | 'DOWN',
    details: Record<string, unknown> = {},
  ) {
    const db = this.getDb();
    if (!db) return null;

    const created = await db.systemHealthSnapshot.create({
      data: {
        service_name: serviceName,
        status,
        response_time_ms: 10,
        error_count: 0,
        details: details as never,
      },
    });

    // CONFLICT-RESOLVED: Tuần tự hóa toàn bộ cột BigInt (id, storage_used_bytes, storage_total_bytes) sang chuỗi để Fastify JSON.stringify không sinh lỗi 500.
    return {
      id: created.id.toString(),
      capturedAt: created.captured_at.toISOString(),
      serviceName: created.service_name,
      status: created.status,
      responseTimeMs: created.response_time_ms,
      storageUsedBytes: created.storage_used_bytes?.toString() ?? null,
      storageTotalBytes: created.storage_total_bytes?.toString() ?? null,
      errorCount: created.error_count,
      details: created.details,
    };
  }

  /**
   * Thuật toán: Thu dọn có giới hạn thời gian lưu trữ các ảnh chụp sức khỏe cũ và công việc xuất báo cáo hết hạn.
   */
  async runRetentionCleanup(retentionDays = 90) {
    const db = this.getDb();
    if (!db) {
      return { deletedSnapshots: 0, deletedExpiredExports: 0 };
    }
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const now = new Date();
    const [snapshots, exports] = await Promise.all([
      db.systemHealthSnapshot.deleteMany({ where: { captured_at: { lt: cutoff } } }),
      db.asyncExportJob.deleteMany({ where: { expires_at: { lt: now } } }),
    ]);
    return {
      deletedSnapshots: snapshots.count,
      deletedExpiredExports: exports.count,
    };
  }

  /**
   * Thuật toán: Truy vấn danh sách ảnh chụp sức khỏe lịch sử sắp xếp giảm dần theo thời điểm ghi nhận.
   */
  async listBusinessSnapshots(limit = 20) {
    const db = this.getDb();
    if (!db) return [];

    const items = await db.systemHealthSnapshot.findMany({
      take: limit,
      orderBy: { captured_at: 'desc' },
    });

    return items.map((s) => ({
      id: s.id.toString(),
      capturedAt: s.captured_at.toISOString(),
      serviceName: s.service_name,
      status: s.status,
      responseTimeMs: s.response_time_ms,
      storageUsedBytes: s.storage_used_bytes?.toString() ?? null,
      storageTotalBytes: s.storage_total_bytes?.toString() ?? null,
      errorCount: s.error_count,
      details: s.details,
    }));
  }

  private getDb() {
    if (this.databaseClient) return this.databaseClient;
    try {
      return getDatabaseClient();
    } catch {
      return null;
    }
  }
}
