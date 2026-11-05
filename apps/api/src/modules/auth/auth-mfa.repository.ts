/**
 * @module AuthMfaRepository
 * Algorithm: TOTP / WebAuthn MFA Factor Persistence, Recovery Code Consumption & Security Alert Sink.
 */
import { randomUUID } from 'node:crypto';
import { ConflictException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import type { getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ActiveMfaMethodRecord {
  id: string;
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
 * Algorithm / Thuật toán: Truy vấn phương thức MFA đang chờ kích hoạt của người dùng.
 */
export async function findPendingMfaMethod(
  database: PrismaClient,
  userId: bigint,
): Promise<{ id: string; encryptedSecret: string } | null> {
  const method = await database.mfaMethod.findFirst({
    where: { user_id: userId, verified_at: null, disabled_at: null },
  });
  return method ? { id: method.id, encryptedSecret: method.secret_encrypted } : null;
}

/**
 * Algorithm / Thuật toán: Kích hoạt nguyên tử phương thức MFA và lưu mảng băm mã khôi phục một lần.
 */
export async function enableUserMfaMethod(
  database: PrismaClient,
  methodId: string,
  userId: bigint,
  recoveryHashes: string[],
): Promise<void> {
  await database.mfaMethod.updateMany({
    where: { id: methodId, user_id: userId, verified_at: null, disabled_at: null },
    data: {
      verified_at: new Date(),
      enabled_at: new Date(),
      recovery_code_hashes: recoveryHashes,
    },
  });
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
 * Algorithm / Thuật toán: Cập nhật danh sách mã khôi phục còn lại sau khi tiêu thụ một mã.
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

/**
 * Algorithm / Thuật toán: Cập nhật bản mã bí mật MFA (ví dụ tăng bộ đếm chữ ký WebAuthn).
 */
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

/**
 * Algorithm / Thuật toán: Liệt kê các nhân tố MFA đang kích hoạt của người dùng theo thứ tự mới nhất.
 */
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
    encryptedSecret: m.secret_encrypted,
    label: m.label,
    recoveryCodeHashes: Array.isArray(m.recovery_code_hashes)
      ? (m.recovery_code_hashes as string[])
      : [],
    createdAt: m.created_at,
  }));
}

/**
 * Algorithm / Thuật toán: Vô hiệu hóa toàn bộ nhân tố MFA đang hoạt động của tài khoản.
 */
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

/**
 * Algorithm / Thuật toán: Ghi nhận cảnh báo an ninh (ví dụ phát hiện nhân bản khóa WebAuthn).
 */
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
