import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Thuật toán: Hợp Nhất Điều Kiện & Khử Xung Đột Lớp Tiện Ích Tailwind CSS (Conditional Class Composition & Conflict Resolution)
 * Mục đích: Kết hợp danh sách lớp CSS động và loại bỏ các quy tắc Tailwind chồng chéo theo thứ tự ưu tiên khai báo sau cùng.
 * Cơ chế hoạt động:
 *   - Bước 1: Chuẩn hóa mảng/đối tượng điều kiện thành chuỗi lớp phẳng qua `clsx`.
 *   - Bước 2: Phân tích nhóm thuộc tính CSS qua `tailwind-merge` để giữ lại lớp đặc tả cuối cùng của mỗi nhóm xung đột.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
