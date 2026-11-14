/**
 * Module: Zero-Trust Public Endpoint Metadata Predicate (`@sda/security`)
 * Thuật toán: So Khớp Đẳng Thức Tuyệt Đối Cờ Siêu Dữ Liệu Máy Chủ (`Strict Boolean Identity Guard`).
 *   - Chỉ chấp nhận duy nhất hằng số boolean `true` được gắn tường minh từ decorator phía máy chủ (`@Public()`).
 *   - Tuyệt đối không ép kiểu truthy (`Boolean(...)`) và không đọc dữ liệu từ request body, header, query hoặc client principal,
 *     đảm bảo cơ chế từ chối mặc định (Default-Deny) trước khi chuyển tiếp sang bộ đánh giá chính sách RBAC/ABAC.
 */
export function isExplicitlyPublicEndpoint(serverMetadata: unknown): serverMetadata is true {
  return serverMetadata === true;
}
