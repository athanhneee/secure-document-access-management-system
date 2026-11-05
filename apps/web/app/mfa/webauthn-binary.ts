import {
  browserSupportsWebAuthn,
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { apiClient, ApiError } from '@/lib/api-client';

/**
 * Algorithm / Thuật toán: Chuyển Đổi Hai Chiều Nhị Phân Khóa Công Khai RFC 4648 §5 Base64URL <-> Uint8Array
 * Mục đích: Chuẩn hóa dữ liệu thách thức mật mã (`challenge`, `credential.id`, `signature`) không chứa ký tự đệm `=` hoặc ký tự không an toàn URL (`+`, `/`) phục vụ giao thức W3C WebAuthn.
 * Cơ chế hoạt động:
 *   - Giải mã (`base64UrlToUint8Array`): Thay thế `-` -> `+`, `_` -> `/`, bù độ dài chia hết cho 4 bằng `=`, giải mã chuỗi nhị phân sang mảng byte `Uint8Array`.
 *   - Mã hóa (`uint8ArrayToBase64Url`): Ghép chuỗi mã ký tự Latin-1 từ bộ đệm nhị phân, mã hóa Base64 chuẩn và cắt bỏ dấu đệm `=` cuối chuỗi sau khi ánh xạ sang bảng chữ cái an toàn URL.
 */
export function base64UrlToUint8Array(base64Url: string): Uint8Array {
  const normalized = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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
  if (err instanceof Error && err.name === 'NotAllowedError') {
    return 'Yêu cầu xác thực khóa phần cứng đã bị hủy hoặc quá thời gian.';
  }
  if (err instanceof ApiError) {
    return (
      err.message || 'Không tìm thấy khóa bảo mật FIDO2 khớp với tài khoản, hoặc xác thực thất bại.'
    );
  }
  if (err instanceof Error) {
    return err.message || 'Không thể xác thực qua FIDO2/Passkey. Vui lòng thử lại hoặc dùng TOTP.';
  }
  return 'Không thể xác thực qua FIDO2/Passkey. Vui lòng thử lại hoặc dùng TOTP.';
}
