export interface PasswordStrengthAssessment {
  hasMinLength: boolean;
  hasUpper: boolean;
  hasLower: boolean;
  hasNumber: boolean;
  hasSpecial: boolean;
  strengthScore: number;
  strengthLabel: string;
  barClassName: string;
}

/**
 * Algorithm / Thuật toán: Chấm Điểm Độ Mạnh Mật Khẩu Đa Tiêu Chí (Multi-Criteria Password Entropy & Complexity Scoring)
 * Mục đích: Ước lượng trực quan mức độ phức tạp của mật khẩu mới trên thang điểm rời rạc `[0..5]` để hướng dẫn người dùng chọn mật khẩu chống vét cạn (Brute-Force / Dictionary Attack).
 * Cơ chế hoạt động:
 *   - Đánh giá độc lập `O(N)` 5 tiêu chí trực giao: ngưỡng chiều dài tối thiểu (`>= 15`), chữ cái in hoa (`[A-Z]`), chữ cái thường (`[a-z]`), chữ số (`[0-9]`) và ký tự đặc biệt (`[^A-Za-z0-9]`).
 *   - Đếm tổng số vị từ thỏa mãn tạo thành `strengthScore` và phân hoạch thành 3 ngưỡng cảnh báo trực quan: Yếu (`<= 2`), Khá (`3..4`) và Rất mạnh (`5`).
 */
export function evaluatePasswordStrength(password: string): PasswordStrengthAssessment {
  const hasMinLength = password.length >= 15;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const strengthScore = [hasMinLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(
    Boolean,
  ).length;

  const strengthLabel =
    strengthScore <= 2 ? 'Yếu' : strengthScore <= 4 ? 'Khá' : 'Rất mạnh (Khuyến nghị)';
  const barClassName =
    strengthScore <= 2
      ? 'w-1/3 bg-[#C13515]'
      : strengthScore <= 4
        ? 'w-2/3 bg-[#E07912]'
        : 'w-full bg-[#008A05]';

  return {
    hasMinLength,
    hasUpper,
    hasLower,
    hasNumber,
    hasSpecial,
    strengthScore,
    strengthLabel,
    barClassName,
  };
}
