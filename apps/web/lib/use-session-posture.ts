'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient } from './api-client';
import {
  resolveDocumentAccessPrecheck,
  type DocumentAccessPrecheckResult,
  type SessionSecurityPosture,
} from './api-error-messages';
import { getOrCreateDeviceFingerprint } from './device-fingerprint';

export {
  resolveDocumentAccessPrecheck,
  type DocumentAccessPrecheckResult,
  type SessionSecurityPosture,
};

function isValidSessionPosturePayload(value: unknown): value is SessionSecurityPosture {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj['mfaVerified'] === 'boolean' &&
    typeof obj['mfaEnabled'] === 'boolean' &&
    typeof obj['trustedNetwork'] === 'boolean' &&
    typeof obj['deviceTrust'] === 'boolean' &&
    typeof obj['riskScore'] === 'number' &&
    Number.isFinite(obj['riskScore']) &&
    typeof obj['riskThreshold'] === 'number' &&
    typeof obj['highRiskBlocked'] === 'boolean' &&
    Array.isArray(obj['riskFactors'])
  );
}

/**
 * Thuật toán: Nạp & Làm Mới Trạng Thái Bảo Mật Cấp Phiên Không Gây Lỗi Chặn Trang (`useSessionPosture`)
 */
export function useSessionPosture(enabled: boolean) {
  const [posture, setPosture] = useState<SessionSecurityPosture | null>(null);
  const [isLoadingPosture, setIsLoadingPosture] = useState(false);

  const refreshPosture = useCallback(async () => {
    if (!enabled) {
      setPosture(null);
      return;
    }
    setIsLoadingPosture(true);
    try {
      const deviceFingerprint = getOrCreateDeviceFingerprint();
      const headers: Record<string, string> = {};
      if (deviceFingerprint) {
        headers['x-device-fingerprint'] = deviceFingerprint;
      }
      const res = await apiClient<unknown>('/auth/session-posture', { headers });
      if (isValidSessionPosturePayload(res)) {
        setPosture(res);
      }
    } catch {
      // Giữ trải nghiệm ổn định nếu kiểm tra trạng thái phiên tạm thời lỗi; PEP máy chủ vẫn kiểm định đầy đủ khi mở tài liệu
    } finally {
      setIsLoadingPosture(false);
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshPosture();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [enabled, refreshPosture]);

  return {
    posture: enabled ? posture : null,
    isLoadingPosture: enabled ? isLoadingPosture : false,
    refreshPosture,
  };
}
