'use client';

import * as React from 'react';

export interface DialogErrorContextValue {
  errorMessage: string | null;
  onDismiss?: (() => void) | undefined;
}

export const DialogErrorContext = React.createContext<DialogErrorContextValue>({
  errorMessage: null,
  onDismiss: undefined,
});

/**
 * Thuật toán: Ngữ cảnh Hiển thị Lỗi Tầng Top-Layer Cho Hộp thoại `<dialog>` (`DialogErrorProvider`)
 * Mục đích: Chuyển tiếp thông báo lỗi từ từng không gian làm việc vào bên trong phần tử `<dialog>` đang mở bằng `.showModal()` để không bị che khuất dưới lớp `::backdrop`.
 */
export function DialogErrorProvider({
  errorMessage,
  onDismiss,
  children,
}: DialogErrorContextValue & { children: React.ReactNode }) {
  const value = React.useMemo(() => ({ errorMessage, onDismiss }), [errorMessage, onDismiss]);
  return <DialogErrorContext.Provider value={value}>{children}</DialogErrorContext.Provider>;
}
