/**
 * Module: Chốt chặn Kiểm soát Truy cập Mặc định Từ chối (Default-Deny / Fail-Closed Guard)
 * Thuật toán: Kiểm chứng siêu dữ liệu khai báo công khai tường minh theo nguyên lý Fail-Safe Defaults.
 */
import { Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { isExplicitlyPublicEndpoint } from '@sda/security';
import { PUBLIC_ENDPOINT_METADATA } from './public-endpoint.js';

@Injectable()
export class DefaultDenyGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  /**
   * Thuật toán: Quyết định Cấp phép Mặc định Từ chối (Fail-Closed Endpoint Authorization)
   * Mục đích: Đảm bảo bất kỳ endpoint nào chưa được đánh dấu công khai một cách tường minh và hợp lệ
   *   sẽ tự động bị chặn lại thay vì vô tình mở quyền truy cập ẩn danh.
   * Cơ chế hoạt động:
   *   - Đọc siêu dữ liệu `PUBLIC_ENDPOINT_METADATA` gắn trực tiếp trên hàm xử lý đích (`context.getHandler()`).
   *   - Ủy quyền thẩm định cấu trúc khai báo cho hàm bất biến `isExplicitlyPublicEndpoint` từ gói bảo mật;
   *     chỉ cho phép đi qua (`true`) khi khai báo công khai hợp lệ, mọi trường hợp thiếu hoặc sai đều trả `false`.
   */
  canActivate(context: ExecutionContext): boolean {
    const declaration = this.reflector.get<unknown>(PUBLIC_ENDPOINT_METADATA, context.getHandler());
    return isExplicitlyPublicEndpoint(declaration);
  }
}
