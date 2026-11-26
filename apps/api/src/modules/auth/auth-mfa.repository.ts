/**
 * @module AuthMfaRepository
 * Algorithm: TOTP / WebAuthn MFA Factor Persistence, Recovery Code Consumption & Security Alert Sink.
 */
import { randomUUID } from 'node:crypto';
import { ConflictException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { withSerializableTransaction, type getDatabaseClient, type Prisma } from '@sda/database';
import { isPrivilegedSeparationRoleOrCapability } from '../rbac/permission-matrix.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export type DisableSingleMfaMethodResult =
  | {
      kind: 'disabled';
      remainingCount: number;
      methodType: 'TOTP' | 'WEBAUTHN';
      label: string | null;
    }
  | { kind: 'not_found' }
  | { kind: 'mandatory_role_last_factor' };

export type DisableAllMfaMethodsResult =
  { kind: 'disabled'; disabledCount: number } | { kind: 'mandatory_role_blocked' };

export interface ActiveMfaMethodRecord {
  id: string;
  methodType: 'TOTP' | 'WEBAUTHN';
  encryptedSecret: string;
  label: string | null;
  recoveryCodeHashes: string[];
  createdAt: Date;
}

/**
 * Algorithm / Thuật toán: Khởi tạo hoặc ghi đè bản ghi đăng ký TOTP chờ xác minh / tạo mới khóa WebAuthn.
 */
export async function createUserMfaEnrollment(
  database: PrismaClient,
  userId: bigint,
  encryptedSecret: string,
  label?: string,
  methodType: 'TOTP' | 'WEBAUTHN' = 'TOTP',
): Promise<string> {
  if (methodType === 'TOTP') {
    // CONFLICT-RESOLVED: Chặn đăng ký trùng TOTP đã kích hoạt bằng lỗi 409 trước khi chạm ràng buộc duy nhất uq_mfa_active_totp_per_user (HIGH-12)
    const alreadyEnabled = await database.mfaMethod.findFirst({
      where: {
        user_id: userId,
        method_type: 'TOTP',
        enabled_at: { not: null },
        disabled_at: null,
      },
      select: { id: true, enabled_at: true },
    });
    if (
      alreadyEnabled &&
      (!('enabled_at' in alreadyEnabled) || alreadyEnabled.enabled_at !== null)
    ) {
      throw new ConflictException({
        errorCode: AppErrorCode.RESOURCE_CONFLICT,
        message: 'An active TOTP authenticator is already enabled for this account.',
      });
    }

    const existing = await database.mfaMethod.findFirst({
      where: {
        user_id: userId,
        method_type: 'TOTP',
        enabled_at: null,
        verified_at: null,
        disabled_at: null,
      },
    });
    if (existing) {
      await database.mfaMethod.update({
        where: { id: existing.id },
        data: {
          secret_encrypted: encryptedSecret,
          label: label ?? null,
          verified_at: null,
          enabled_at: null,
          recovery_code_hashes: [],
        },
      });
      return existing.id;
    }
  }
  const id = randomUUID();
  await database.mfaMethod.create({
    data: {
      id,
      user_id: userId,
      method_type: methodType,
      secret_encrypted: encryptedSecret,
      label: label ?? null,
    },
  });
  return id;
}

/**
 * Algorithm / Thuật toán: Truy vấn phương thức TOTP MFA đang chờ kích hoạt của người dùng (lọc đúng `method_type: 'TOTP'`, BUG-109).
 */
export async function findPendingMfaMethod(
  database: PrismaClient,
  userId: bigint,
): Promise<{ id: string; encryptedSecret: string } | null> {
  const method = await database.mfaMethod.findFirst({
    where: { user_id: userId, method_type: 'TOTP', verified_at: null, disabled_at: null },
  });
  return method ? { id: method.id, encryptedSecret: method.secret_encrypted } : null;
}

/**
 * Algorithm / Thuật toán: Kích hoạt nguyên tử phương thức MFA CAS (`count === 1`) và lưu mảng băm mã khôi phục một lần (BUG-109).
 */
export async function enableUserMfaMethod(
  database: PrismaClient,
  methodId: string,
  userId: bigint,
  recoveryHashes: string[],
): Promise<void> {
  const updated = await database.mfaMethod.updateMany({
    where: { id: methodId, user_id: userId, verified_at: null, disabled_at: null },
    data: {
      verified_at: new Date(),
      enabled_at: new Date(),
      recovery_code_hashes: recoveryHashes,
    },
  });
  if (updated.count !== 1) {
    throw new ConflictException({
      errorCode: AppErrorCode.RESOURCE_CONFLICT,
      message: 'MFA enrollment is no longer pending or was modified concurrently.',
    });
  }
}

/**
 * Algorithm / Thuật toán: Tiêu thụ nguyên tử một lần mã khôi phục MFA bằng khóa bi quan mức dòng (`SELECT ... FOR UPDATE`).
 * Mục đích: Triệt tiêu điều kiện tranh chấp TOCTOU khi nhiều yêu cầu song song gửi cùng một mã khôi phục dự phòng.
 */
export async function consumeMfaRecoveryCodeAtomic(
  database: PrismaClient,
  userId: bigint,
  candidateCode: string,
  consumeFn: (hashes: string[], candidate: string) => string[] | null,
): Promise<boolean> {
  return database.$transaction(async (transaction) => {
    const lockedRows = await transaction.$queryRaw<
      Array<{ id: string; recovery_code_hashes: unknown }>
    >`SELECT id::text AS id, recovery_code_hashes
      FROM public.mfa_methods
      WHERE user_id = ${userId}
        AND enabled_at IS NOT NULL
        AND disabled_at IS NULL
      ORDER BY created_at DESC
      FOR UPDATE`;

    for (const row of lockedRows) {
      const currentHashes = Array.isArray(row.recovery_code_hashes)
        ? row.recovery_code_hashes.filter((item): item is string => typeof item === 'string')
        : [];
      const remaining = consumeFn(currentHashes, candidateCode);
      if (remaining) {
        await transaction.mfaMethod.update({
          where: { id: row.id },
          data: { recovery_code_hashes: remaining },
        });
        return true;
      }
    }
    return false;
  });
}

/**
 * Algorithm / Thuật toán: Nâng bộ đếm chữ ký WebAuthn nguyên tử dưới khóa dòng `FOR UPDATE` chống phát lại song song.
 */
export async function advanceWebAuthnCounterAtomic<TCred extends { counter: number }>(
  database: PrismaClient,
  methodId: string,
  userId: bigint,
  newCounter: number,
  parseFn: (encryptedSecret: string) => TCred | null,
  encryptFn: (updated: TCred) => string,
): Promise<'updated' | 'clone_detected' | 'not_found'> {
  return database.$transaction(async (transaction) => {
    const lockedRows = await transaction.$queryRaw<
      Array<{ id: string; secret_encrypted: string }>
    >`SELECT id::text AS id, secret_encrypted
      FROM public.mfa_methods
      WHERE id = ${methodId}::uuid
        AND user_id = ${userId}
        AND enabled_at IS NOT NULL
        AND disabled_at IS NULL
      FOR UPDATE`;

    const row = lockedRows[0];
    if (!row) return 'not_found';
    const freshCred = parseFn(row.secret_encrypted);
    if (!freshCred) return 'not_found';

    if ((freshCred.counter > 0 || newCounter > 0) && newCounter <= freshCred.counter) {
      return 'clone_detected';
    }

    const updatedSecret = encryptFn({ ...freshCred, counter: newCounter });
    await transaction.mfaMethod.update({
      where: { id: row.id },
      data: { secret_encrypted: updatedSecret },
    });
    return 'updated';
  });
}

/**
 * Algorithm / Thuật toán: Cập nhật mã khôi phục còn lại, bí mật MFA, danh sách nhân tố hoạt động, vô hiệu hóa MFA và ghi cảnh báo.
 */
export async function consumeMfaRecoveryCode(
  database: PrismaClient,
  methodId: string,
  hashes: string[],
): Promise<void> {
  await database.mfaMethod.update({
    where: { id: methodId },
    data: { recovery_code_hashes: hashes },
  });
}

export async function updateUserMfaSecret(
  database: PrismaClient,
  methodId: string,
  encryptedSecret: string,
): Promise<void> {
  await database.mfaMethod.update({
    where: { id: methodId },
    data: { secret_encrypted: encryptedSecret },
  });
}

export async function listActiveMfaMethods(
  database: PrismaClient,
  userId: bigint,
): Promise<ActiveMfaMethodRecord[]> {
  const methods = await database.mfaMethod.findMany({
    where: { user_id: userId, enabled_at: { not: null }, disabled_at: null },
    orderBy: { created_at: 'desc' },
  });
  return methods.map((m) => ({
    id: m.id,
    methodType: m.method_type === 'WEBAUTHN' ? 'WEBAUTHN' : 'TOTP',
    encryptedSecret: m.secret_encrypted,
    label: m.label,
    recoveryCodeHashes: Array.isArray(m.recovery_code_hashes)
      ? (m.recovery_code_hashes as string[])
      : [],
    createdAt: m.created_at,
  }));
}

/**
 * Thuật toán: Kiểm Tra Vai Trò & Năng Lực Đặc Quyền Bắt Buộc MFA Trực Tiếp Trong Giao Dịch DB (`hasLiveMandatoryMfaRoleInTx`).
 * Mục đích: Đọc danh sách vai trò còn hiệu lực (`user_roles` -> `roles` -> `role_permissions` -> `permissions`) ngay trong giao dịch `SERIALIZABLE`
 *   để phát hiện cả vai trò hệ thống (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`) lẫn Custom Role mang quyền đặc quyền.
 */
async function hasLiveMandatoryMfaRoleInTx(
  transaction: Prisma.TransactionClient,
  userId: bigint,
  now: Date,
): Promise<boolean> {
  const assignments = await transaction.userRole.findMany({
    where: {
      user_id: userId,
      valid_from: { lte: now },
      AND: [
        { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
        { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
      ],
      roles: { is_active: true },
    },
    include: {
      roles: {
        include: {
          role_permissions: {
            include: {
              permissions: { select: { code: true, resource_type: true, action: true } },
            },
          },
        },
      },
    },
  });

  return assignments.some((assignment) =>
    isPrivilegedSeparationRoleOrCapability(
      assignment.roles.code,
      (assignment.roles.role_permissions ?? [])
        .map((rp) => rp.permissions ?? undefined)
        .filter((perm): perm is NonNullable<typeof perm> => perm !== undefined),
    ),
  );
}

/**
 * Thuật toán: Gỡ Nguyên Tử Một Nhân Tố MFA Đơn Lẻ Trong Giao Dịch `SERIALIZABLE` Kèm Khóa `SELECT ... FOR UPDATE` (`disableSingleUserMfaMethodAtomic`, BUG-003).
 * Mục đích: Triệt tiêu hoàn toàn điều kiện tranh chấp TOCTOU khi gửi song song nhiều lệnh gỡ nhân tố MFA của tài khoản đặc quyền,
 *   khóa tuần tự bản ghi `users` rồi khóa toàn bộ `mfa_methods` đang hoạt động và kiểm tra `isPrivilegedSeparationRoleOrCapability` trên dữ liệu DB mới nhất.
 */
export async function disableSingleUserMfaMethodAtomic(
  database: PrismaClient,
  userId: bigint,
  methodId: string,
): Promise<DisableSingleMfaMethodResult> {
  return withSerializableTransaction(
    async (transaction) => {
      const now = new Date();
      await transaction.$queryRaw<Array<{ id: bigint }>>`SELECT id
        FROM public.users
        WHERE id = ${userId}
        FOR UPDATE`;

      const lockedRows = await transaction.$queryRaw<
        Array<{
          id: string;
          method_type: string;
          label: string | null;
          recovery_code_hashes: unknown;
        }>
      >`SELECT id::text AS id, method_type::text AS method_type, label, recovery_code_hashes
        FROM public.mfa_methods
        WHERE user_id = ${userId}
          AND enabled_at IS NOT NULL
          AND disabled_at IS NULL
        ORDER BY id ASC
        FOR UPDATE`;

      const target = lockedRows.find((row) => row.id === methodId);
      if (!target) {
        return { kind: 'not_found' };
      }

      const requiresMandatoryMfa = await hasLiveMandatoryMfaRoleInTx(transaction, userId, now);
      const remainingRows = lockedRows.filter((row) => row.id !== methodId);
      const remainingCount = remainingRows.length;
      if (requiresMandatoryMfa && remainingCount < 1) {
        return { kind: 'mandatory_role_last_factor' };
      }

      // Thuật toán: Di trú bộ mã khôi phục chưa sử dụng sang nhân tố MFA còn sống nếu nhân tố sắp gỡ đang giữ bộ mã khôi phục duy nhất (LOW-06).
      const targetRecoveryHashes = Array.isArray(target.recovery_code_hashes)
        ? (target.recovery_code_hashes as string[])
        : [];
      const anySurvivorHasRecoveryCodes = remainingRows.some(
        (row) => Array.isArray(row.recovery_code_hashes) && row.recovery_code_hashes.length > 0,
      );
      if (
        targetRecoveryHashes.length > 0 &&
        !anySurvivorHasRecoveryCodes &&
        remainingRows.length > 0 &&
        typeof transaction.mfaMethod?.update === 'function'
      ) {
        await transaction.mfaMethod.update({
          where: { id: remainingRows[0]!.id },
          data: { recovery_code_hashes: targetRecoveryHashes },
        });
      }

      const updated = await transaction.mfaMethod.updateMany({
        where: {
          id: methodId,
          user_id: userId,
          enabled_at: { not: null },
          disabled_at: null,
        },
        data: {
          disabled_at: now,
          ...(targetRecoveryHashes.length > 0 &&
          !anySurvivorHasRecoveryCodes &&
          remainingRows.length > 0
            ? { recovery_code_hashes: [] }
            : {}),
        },
      });
      if (updated.count === 0) {
        return { kind: 'not_found' };
      }

      return {
        kind: 'disabled',
        remainingCount,
        methodType: target.method_type === 'WEBAUTHN' ? 'WEBAUTHN' : 'TOTP',
        label: target.label,
      };
    },
    { client: database },
  );
}

/**
 * Thuật toán: Tắt Toàn Bộ Nhân Tố MFA Trong Giao Dịch `SERIALIZABLE` Kèm Khóa `SELECT ... FOR UPDATE` (`disableUserMfaMethodsAtomic`, BUG-003).
 * Mục đích: Đảm bảo vai trò hệ thống hoặc Custom Role đặc quyền mới được gán đồng thời không bao giờ bị vô hiệu hóa sạch MFA.
 */
export async function disableUserMfaMethodsAtomic(
  database: PrismaClient,
  userId: bigint,
): Promise<DisableAllMfaMethodsResult> {
  return withSerializableTransaction(
    async (transaction) => {
      const now = new Date();
      await transaction.$queryRaw<Array<{ id: bigint }>>`SELECT id
        FROM public.users
        WHERE id = ${userId}
        FOR UPDATE`;

      await transaction.$queryRaw<Array<{ id: string }>>`SELECT id::text AS id
        FROM public.mfa_methods
        WHERE user_id = ${userId}
          AND enabled_at IS NOT NULL
          AND disabled_at IS NULL
        ORDER BY id ASC
        FOR UPDATE`;

      const requiresMandatoryMfa = await hasLiveMandatoryMfaRoleInTx(transaction, userId, now);
      if (requiresMandatoryMfa) {
        return { kind: 'mandatory_role_blocked' };
      }

      const updated = await transaction.mfaMethod.updateMany({
        where: { user_id: userId, enabled_at: { not: null }, disabled_at: null },
        data: { disabled_at: now },
      });
      return { kind: 'disabled', disabledCount: updated.count };
    },
    { client: database },
  );
}

/**
 * Thuật toán: Gỡ Bỏ Một Nhân Tố MFA Đơn Lẻ (Passkey / TOTP) Có Kiểm Tra Chủ Sở Hữu (`disableSingleUserMfaMethod`, V-48).
 */
export async function disableSingleUserMfaMethod(
  database: PrismaClient,
  userId: bigint,
  methodId: string,
): Promise<boolean> {
  const result = await database.mfaMethod.updateMany({
    where: {
      id: methodId,
      user_id: userId,
      enabled_at: { not: null },
      disabled_at: null,
    },
    data: { disabled_at: new Date() },
  });
  return result.count > 0;
}

export async function disableUserMfaMethods(
  database: PrismaClient,
  userId: bigint,
): Promise<boolean> {
  const result = await database.mfaMethod.updateMany({
    where: { user_id: userId, enabled_at: { not: null }, disabled_at: null },
    data: { disabled_at: new Date() },
  });
  return result.count > 0;
}

export async function insertSecurityAlert(
  database: PrismaClient,
  data: {
    alertType: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    description: string;
    detectedUserId?: bigint;
  },
): Promise<void> {
  await database.securityAlert.create({
    data: {
      id: randomUUID(),
      alert_type: data.alertType,
      severity: data.severity,
      title: data.title,
      description: data.description,
      detected_user_id: data.detectedUserId ?? null,
    },
  });
}
