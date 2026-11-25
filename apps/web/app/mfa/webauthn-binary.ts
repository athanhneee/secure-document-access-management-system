/**
 * Algorithm / Thuật toán: Giải Mã Nhị Phân Khóa Công Khai RFC 4648 §5 Base64URL -> Uint8Array, Đăng Ký & Xác Thực W3C WebAuthn
 * Mục đích:
 *   - Giải mã chuỗi `challenge` Base64URL sang `Uint8Array` nội bộ để kiểm định entropy tối thiểu 16 byte trước khi kích hoạt đăng ký (`startRegistration`) hoặc ký số xác thực (`startAuthentication`) FIDO2 CTAP2.
 *   - Tự nhận diện địa chỉ IP loopback (`127.0.0.1`) vốn bị chuẩn trình duyệt W3C WebAuthn chặn để hướng dẫn người dùng chuyển mượt sang `http://localhost:...`.
 */
import { useSyncExternalStore } from 'react';
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { apiClient, ApiError } from '@/lib/api-client';

function base64UrlToUint8Array(base64Url: string): Uint8Array {
  const normalized = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Thuật toán: Kiểm Tra Origin Đang Truy Cập Bằng IP Loopback (`getLocalhostSwitchUrl`)
 * Mục đích: Chuẩn W3C WebAuthn yêu cầu Relying Party ID là tên miền hợp lệ (như `localhost`), không chấp nhận IP thô `127.0.0.1`. Hàm trả về URL `localhost` tương đương nếu người dùng đang mở bằng `127.0.0.1`.
 */
export function getLocalhostSwitchUrl(): string | null {
  if (typeof window === 'undefined') return null;
  if (window.location.hostname !== '127.0.0.1') return null;
  const nextUrl = new URL(window.location.href);
  nextUrl.hostname = 'localhost';
  return nextUrl.toString();
}

const subscribeNoop = () => () => {};
const getServerNullSnapshot = (): string | null => null;

/**
 * Thuật toán: Đọc An Toàn URL Chuyển Đổi `localhost` Không Gây Lệch Hydration (`useLocalhostSwitchUrl`)
 * Mục đích: Trả về `null` ở pha SSR/Hydration và tự đồng bộ sang `getLocalhostSwitchUrl()` ở phía trình duyệt bằng `useSyncExternalStore`.
 */
export function useLocalhostSwitchUrl(): string | null {
  return useSyncExternalStore(subscribeNoop, getLocalhostSwitchUrl, getServerNullSnapshot);
}

/**
 * Algorithm / Thuật toán: Đăng Ký Khóa Bảo Mật Phần Cứng / Passkey W3C WebAuthn Level 3 (`executeWebAuthnRegistration`)
 * Cơ chế hoạt động:
 *   - Bước 1: Kiểm tra hỗ trợ WebAuthn và gọi `POST /auth/mfa/webauthn/register/options` để lấy thử thách mật mã kèm `challengeToken` ký HMAC.
 *   - Bước 2: Kiểm định entropy thử thách tối thiểu 16 byte sau giải mã nhị phân, kích hoạt `navigator.credentials.create` qua `startRegistration`.
 *   - Bước 3: Gửi `RegistrationResponseJSON` kèm `challengeToken` lên `POST /auth/mfa/webauthn/register/verify` để xác minh, lưu khóa công khai đã mã hóa và nhận 10 mã khôi phục dùng một lần.
 */
export async function executeWebAuthnRegistration(
  label?: string,
): Promise<{ recoveryCodes: string[] }> {
  if (!browserSupportsWebAuthn()) {
    throw new Error('Trình duyệt hiện tại chưa hỗ trợ đăng ký khóa FIDO2 / Passkey.');
  }

  const trimmedLabel = label?.trim();
  const payload = trimmedLabel ? { label: trimmedLabel } : {};

  const { options, challengeToken } = await apiClient<{
    options: PublicKeyCredentialCreationOptionsJSON;
    challengeToken: string;
  }>('/auth/mfa/webauthn/register/options', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!options.challenge || base64UrlToUint8Array(options.challenge).byteLength < 16) {
    throw new Error('Thách thức đăng ký WebAuthn từ máy chủ không hợp lệ.');
  }

  const registrationResponse = await startRegistration({ optionsJSON: options });

  const result = await apiClient<{ recoveryCodes: string[] }>(
    '/auth/mfa/webauthn/register/verify',
    {
      method: 'POST',
      body: JSON.stringify({
        response: registrationResponse,
        challengeToken,
        ...(trimmedLabel ? { label: trimmedLabel } : {}),
      }),
    },
  );

  return { recoveryCodes: Array.isArray(result?.recoveryCodes) ? result.recoveryCodes : [] };
}

/**
 * Algorithm / Thuật toán: Xác Thực Thách Thức - Phản Hồi Khóa Công Khai W3C WebAuthn / FIDO2 CTAP2
 * Mục đích: Thực hiện ký số thách thức mật mã bằng khóa bảo mật vật lý (YubiKey) hoặc sinh trắc học thiết bị chống tấn công Phishing / Man-in-the-Middle.
 * Cơ chế hoạt động:
 *   - Bước 1: Yêu cầu máy chủ sinh `challenge` Base64URL (kiểm tra độ dài entropy tối thiểu 16 byte sau giải mã nhị phân) kèm `challengeToken` ràng buộc phiên.
 *   - Bước 2: Kích hoạt hộp thoại phần cứng `navigator.credentials.get` qua `startAuthentication` và gửi chữ ký `AuthenticatorAssertionResponse` lên `/auth/mfa/webauthn/auth/verify`.
 */
export async function executeWebAuthnAssertion(): Promise<void> {
  if (!browserSupportsWebAuthn()) {
    throw new Error('Trình duyệt hiện tại chưa hỗ trợ xác thực khóa FIDO2 / WebAuthn.');
  }

  const { options, challengeToken } = await apiClient<{
    options: PublicKeyCredentialRequestOptionsJSON;
    challengeToken: string;
  }>('/auth/mfa/webauthn/auth/options', {
    method: 'POST',
    body: JSON.stringify({}),
  });

  if (!options.challenge || base64UrlToUint8Array(options.challenge).byteLength < 16) {
    throw new Error('Thách thức mật mã WebAuthn từ máy chủ không hợp lệ.');
  }

  const authResponse = await startAuthentication({ optionsJSON: options });

  await apiClient<{ authenticated: true }>('/auth/mfa/webauthn/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      response: authResponse,
      challengeToken,
    }),
  });
}

export function formatWebAuthnError(err: unknown): string {
  if (err instanceof Error && err.name === 'SecurityError') {
    const localhostUrl = getLocalhostSwitchUrl();
    return localhostUrl
      ? `Trình duyệt chặn FIDO2 / Passkey trên địa chỉ IP 127.0.0.1. Vui lòng truy cập qua ${localhostUrl} để đăng ký và xác thực.`
      : 'Tên miền hiện tại không khớp với cấu hình Relying Party ID (WEBAUTHN_RP_ID) của hệ thống.';
  }
  if (err instanceof Error && err.name === 'InvalidStateError') {
    return 'Khóa bảo mật hoặc Passkey trên thiết bị này đã được đăng ký cho tài khoản của bạn trước đó.';
  }
  if (err instanceof Error && err.name === 'NotAllowedError') {
    return 'Yêu cầu khóa bảo mật FIDO2 / Passkey đã bị hủy hoặc quá thời gian phản hồi.';
  }
  if (err instanceof ApiError) {
    return (
      err.message || 'Không tìm thấy khóa bảo mật FIDO2 khớp với tài khoản, hoặc xác thực thất bại.'
    );
  }
  if (err instanceof Error) {
    return err.message || 'Không thể xử lý FIDO2 / Passkey. Vui lòng thử lại hoặc dùng TOTP.';
  }
  return 'Không thể xử lý FIDO2 / Passkey. Vui lòng thử lại hoặc dùng TOTP.';
}
