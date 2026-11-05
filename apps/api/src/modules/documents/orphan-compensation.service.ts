/**
 * Module: Dịch vụ Bù trừ Saga Dọn dẹp Tài nguyên Mồ côi (Saga Orphan Compensation Service)
 * Thuật toán: Theo dõi tài nguyên ngoại vi (Object Storage keys & tệp/thư mục tạm trên đĩa) theo phiên tải lên
 *   và thực thi giao dịch bù trừ (Compensating Transaction) chịu lỗi khi quy trình tiếp nhận bị hủy bỏ.
 */
import { Injectable, Logger } from '@nestjs/common';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import { ObjectStorageService } from './object-storage.service.js';

export interface UploadSessionCompensation {
  storageKeysToDelete: Array<{ bucket: string; key: string }>;
  tempFilesToDelete: string[];
}

@Injectable()
export class OrphanCompensationService {
  private readonly logger = new Logger(OrphanCompensationService.name);

  constructor(private readonly storage: ObjectStorageService) {}

  /**
   * Creates a new compensation tracker for an active upload session.
   *
   * Thuật toán: Khởi Tạo Ngữ Cảnh Theo Dõi Bù Trừ Saga (Saga Compensation Log Initialization)
   * Mục đích: Cấp phát danh sách rỗng ghi nhận các đối tượng lưu trữ và đường dẫn tạm phát sinh trong phiên tải lên.
   * Cơ chế hoạt động:
   *   - Trả về cấu trúc `UploadSessionCompensation` độc lập cho từng yêu cầu để tránh xung đột trạng thái đồng thời.
   */
  createSession(): UploadSessionCompensation {
    return {
      storageKeysToDelete: [],
      tempFilesToDelete: [],
    };
  }

  /**
   * Rolls back all tracked storage objects and temp files for a failed upload session.
   *
   * Thuật toán: Thực Thi Giao Dịch Bù Trừ Chịu Lỗi Từng Phần (Best-Effort Saga Compensation Rollback)
   * Mục đích: Thu hồi toàn bộ đối tượng S3/MinIO và tệp tạm chưa kịp gắn kết vào cơ sở dữ liệu khi luồng chính thất bại.
   * Cơ chế hoạt động:
   *   - Pha 1: Duyệt tuần tự `storageKeysToDelete` gọi `deleteObject`, bắt và ghi cảnh báo riêng từng mục để lỗi một mục
   *     không làm ngắt quãng việc dọn dẹp các mục tiếp theo.
   *   - Pha 2: Duyệt `tempFilesToDelete`, kiểm tra `stat` để phân biệt thư mục (`rm` đệ quy) hay tệp đơn (`unlink`) và xóa sạch.
   */
  async compensate(session: UploadSessionCompensation): Promise<void> {
    // 1. Delete tracked storage objects
    for (const item of session.storageKeysToDelete) {
      try {
        await this.storage.deleteObject(item.bucket, item.key);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(
          `Compensation failed to delete storage object ${item.bucket}/${item.key}: ${msg}`,
        );
      }
    }

    // 2. Delete tracked temporary files
    for (const filePath of session.tempFilesToDelete) {
      try {
        if (fs.existsSync(filePath)) {
          const stat = await fsp.stat(filePath).catch(() => null);
          if (stat?.isDirectory()) {
            await fsp.rm(filePath, { recursive: true, force: true }).catch(() => {});
          } else {
            await fsp.unlink(filePath).catch(() => {});
          }
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Compensation failed to delete temp file ${filePath}: ${msg}`);
      }
    }
  }
}
