/**
 * Module: Điểm xuất trung tâm (`@sda/database`) cho kết nối Prisma/PostgreSQL TLS Pool, giao dịch cô lập `SERIALIZABLE` tự động thử lại,
 * bộ ánh xạ lỗi cơ sở dữ liệu an toàn và hằng số kiểm định tổng số bảng nghiệp vụ (`businessTableCount = 39`).
 * Thuật toán: Tái xuất có kiểm soát bề mặt API tầng dữ liệu (Controlled Persistence Facade) nhằm ẩn chi tiết kết nối vật lý `pg.Pool` và adapter nội bộ.
 */
export {
  buildPgPoolConfig,
  createDatabaseClient,
  disconnectDatabase,
  getDatabaseClient,
} from './client.js';
export {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseError,
  DatabaseNotFoundError,
  DatabaseUnavailableError,
  UniqueConstraintError,
  isDatabaseOperationError,
  mapDatabaseError,
} from './errors.js';
export {
  withSerializableTransaction,
  type SerializableTransactionOptions,
  type TransactionOperation,
} from './transaction.js';
export * from './generated/prisma/enums.js';
export type * from './generated/prisma/models.js';
export { Prisma } from './generated/prisma/client.js';

/**
 * Tổng số bảng nghiệp vụ định nghĩa trong `prisma/schema/*.prisma` (31 bảng miền cốt lõi + 8 bảng mở rộng cho xác thực/MFA,
 * điểm neo kiểm toán, phát hiện SOC, hộp thư đi và hàng đợi xuất báo cáo bất đồng bộ).
 */
export const businessTableCount = 39;
