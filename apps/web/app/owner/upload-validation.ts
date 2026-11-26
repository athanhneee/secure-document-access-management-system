import type { DepartmentLookupItem } from './types';

export const MAX_UPLOAD_FILE_SIZE_BYTES = 50 * 1024 * 1024;
export const DOCUMENT_CODE_REGEX = /^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/;

const ALLOWED_UPLOAD_EXTENSIONS = new Set(['pdf', 'docx', 'xlsx', 'pptx']);

const DANGEROUS_FILE_EXTENSIONS = new Set([
  'exe',
  'bat',
  'scr',
  'js',
  'jse',
  'vbs',
  'vbe',
  'cmd',
  'ps1',
  'msi',
  'msp',
  'com',
  'hta',
  'pif',
  'cpl',
  'jar',
  'wsf',
  'wsh',
  'reg',
  'dll',
  'sh',
]);

/**
 * Thuật toán: Kiểm Định Định Dạng Mã Tài Liệu Khớp Lược Đồ Zod Máy Chủ (`validateDocumentCodeInput`, BUG-103)
 * Cho phép để trống (máy chủ tự sinh mã `DOC-...`) hoặc chuỗi 1–60 ký tự bắt đầu bằng chữ/số và chỉ chứa `[A-Za-z0-9_-]`.
 */
export function validateDocumentCodeInput(rawCode: string): string | null {
  const trimmed = rawCode.trim();
  if (!trimmed) return null;
  if (!DOCUMENT_CODE_REGEX.test(trimmed)) {
    return 'Mã tài liệu phải bắt đầu bằng chữ cái hoặc chữ số (tối đa 60 ký tự) và chỉ gồm A-Z, a-z, 0-9, dấu gạch ngang (-) hoặc gạch dưới (_).';
  }
  return null;
}

/**
 * Thuật toán: Kiểm Định Dung Lượng `0 < size <= 50MB` & Chặn Đuôi Kép Thực Thi Nguy Hiểm (`validateUploadFileInput`, BUG-103)
 * Mục đích: Ngăn tệp rỗng, tệp vượt 50MB, tệp ngụy trang phần mở rộng kép (như `.pdf.exe`, `.docx.bat`, `.scr`, `.js`, `.ps1`, `.hta`)
 * ngay từ Bước 1 trước khi truyền tải mạng.
 */
export function validateUploadFileInput(file: File | null | undefined): string | null {
  if (!file) {
    return 'Vui lòng chọn tệp tài liệu trước khi tiếp tục.';
  }
  if (file.size <= 0) {
    return 'Tệp tài liệu đang rỗng (0 byte). Vui lòng chọn tệp hợp lệ.';
  }
  if (file.size > MAX_UPLOAD_FILE_SIZE_BYTES) {
    return 'Kích thước tệp vượt quá giới hạn tối đa 50 MB.';
  }

  const sanitizedName = file.name.trim().replace(/[. ]+$/u, '');
  const segments = sanitizedName.split('.').filter((part) => part.length > 0);
  if (segments.length < 2) {
    return 'Tệp tải lên thiếu phần mở rộng hợp lệ (chỉ hỗ trợ .pdf, .docx, .xlsx, .pptx).';
  }

  const extensionSegments = segments.slice(1).map((ext) => ext.toLowerCase());
  for (const ext of extensionSegments) {
    if (DANGEROUS_FILE_EXTENSIONS.has(ext)) {
      return `Phát hiện phần mở rộng tệp thực thi nguy hiểm (.${ext}). Hệ thống đã chặn tệp để đảm bảo an toàn.`;
    }
  }

  const finalExt = extensionSegments[extensionSegments.length - 1]!;
  if (!ALLOWED_UPLOAD_EXTENSIONS.has(finalExt)) {
    return 'Định dạng tệp không được hỗ trợ. Vui lòng chọn tệp PDF, DOCX, XLSX hoặc PPTX.';
  }

  return null;
}

/**
 * Thuật toán: Lọc Cây Con Phòng Ban Được Phép Tải Lên Bằng Duyệt Chiều Rộng BFS (`filterDepartmentsByUploadScope`, BUG-103)
 * Mục đích: Chỉ hiển thị các phòng ban nằm trong phạm vi tải lên của chủ thể (cây con `userDepartmentId` hoặc `uploadDepartmentIds`
 * trừ khi có quyền toàn cục), ngăn chọn nhầm phòng ban ngoài phạm vi gây lỗi `403` ở Bước 3.
 */
export function filterDepartmentsByUploadScope(params: {
  departments: ReadonlyArray<DepartmentLookupItem>;
  userDepartmentId?: string | number | null | undefined;
  hasGlobalUploadScope?: boolean | undefined;
  uploadDepartmentIds?: readonly (string | number)[] | undefined;
}): DepartmentLookupItem[] {
  const { departments, userDepartmentId, hasGlobalUploadScope, uploadDepartmentIds } = params;
  if (departments.length === 0) return [];
  if (hasGlobalUploadScope === true) return [...departments];

  const rootIds: string[] = [];
  if (Array.isArray(uploadDepartmentIds) && uploadDepartmentIds.length > 0) {
    for (const id of uploadDepartmentIds) {
      const normalized = String(id).trim();
      if (normalized) rootIds.push(normalized);
    }
  } else if (
    userDepartmentId !== null &&
    userDepartmentId !== undefined &&
    String(userDepartmentId).trim() !== ''
  ) {
    rootIds.push(String(userDepartmentId).trim());
  } else {
    return [];
  }

  const childrenByParent = new Map<string, string[]>();
  for (const dept of departments) {
    if (dept.parentId !== null && dept.parentId !== undefined && String(dept.parentId) !== '') {
      const parentKey = String(dept.parentId);
      const list = childrenByParent.get(parentKey);
      if (list) {
        list.push(String(dept.id));
      } else {
        childrenByParent.set(parentKey, [String(dept.id)]);
      }
    }
  }

  const allowedIds = new Set<string>();
  const queue = [...rootIds];
  let head = 0;
  while (head < queue.length) {
    const curr = queue[head++]!;
    if (allowedIds.has(curr)) continue;
    allowedIds.add(curr);
    const children = childrenByParent.get(curr);
    if (children) {
      for (const child of children) {
        if (!allowedIds.has(child)) {
          queue.push(child);
        }
      }
    }
  }

  return departments.filter((d) => allowedIds.has(String(d.id)));
}
