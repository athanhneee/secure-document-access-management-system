/**
 * Thuật toán: Kiểm tra hiệu lực khoảng thời gian nửa mở `[validFrom, validTo)` (Half-Open Temporal Interval Membership).
 * Mục đích: Xác định phép gán thuộc tính có đang hiệu lực tại thời điểm `at` hay không (`validTo = null` tương đương vô hạn).
 */
export function isAssignmentActive(
  assignment: { validFrom: Date; validTo: Date | null },
  at: Date,
): boolean {
  return assignment.validFrom <= at && (assignment.validTo === null || assignment.validTo > at);
}
