'use client';

import { useCallback, useEffect, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

/**
 * Thuật toán: Đồng Bộ Hai Chiều Tham Số Truy Vấn `?tab=` Với Kiểm Chứng Quyền Truy Cập RBAC (`useWorkspaceTabSync`)
 * Mục đích:
 *   - Giữ đồng bộ trạng thái tab đang mở của các phân hệ (`/security`, `/auditor`, `/admin`, `/owner`, `/reader`)
 *     với tham số `?tab=` trên thanh địa chỉ URL mà không cuộn trang (`{ scroll: false }`).
 *   - Chống truy cập trái phép hoặc kẹt tab trống bằng cách chỉ chấp nhận giá trị `tab` nằm trong `allowedTabs`
 *     đã lọc theo quyền RBAC thực tế; tự động lùi về `fallbackTab` hợp lệ đầu tiên khi `?tab=` sai hoặc quyền thay đổi.
 */
export function useWorkspaceTabSync<T extends string>(
  allowedTabs: readonly T[],
  defaultTab?: T,
): [T, (nextTab: T) => void] {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const fallbackTab: T =
    defaultTab && allowedTabs.includes(defaultTab)
      ? defaultTab
      : ((allowedTabs[0] ?? defaultTab ?? ('' as T)) as T);

  const rawUrlTab = searchParams.get('tab');
  const validUrlTab = rawUrlTab && allowedTabs.includes(rawUrlTab as T) ? (rawUrlTab as T) : null;

  const [manualTab, setManualTab] = useState<T>(() => validUrlTab ?? fallbackTab);
  const activeTab: T = validUrlTab ?? (allowedTabs.includes(manualTab) ? manualTab : fallbackTab);

  useEffect(() => {
    if (validUrlTab) {
      return;
    }

    if (rawUrlTab !== null && allowedTabs.length > 0 && fallbackTab) {
      const nextParams = new URLSearchParams(searchParams.toString());
      nextParams.set('tab', fallbackTab);
      const qs = nextParams.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    }
  }, [allowedTabs, fallbackTab, pathname, rawUrlTab, router, searchParams, validUrlTab]);

  const setActiveTab = useCallback(
    (nextTab: T) => {
      if (!allowedTabs.includes(nextTab)) {
        return;
      }
      setManualTab(nextTab);
      const nextParams = new URLSearchParams(searchParams.toString());
      nextParams.set('tab', nextTab);
      const qs = nextParams.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [allowedTabs, pathname, router, searchParams],
  );

  return [activeTab, setActiveTab];
}
