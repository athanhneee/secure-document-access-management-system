-- Thuật toán tổng quan migration:
-- Bổ sung cột `version` phục vụ kiểm soát đồng thời lạc quan (Optimistic Concurrency Control) cho quản trị RBAC phân cấp (`departments`, `roles`, `users`)
-- và thiết lập trigger bảo toàn cấu trúc cây có hướng không chu trình (DAG / Tree Hierarchy) trên bảng `departments`.
ALTER TABLE departments ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roles ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 0;

-- Thuật toán: Phát hiện chu trình đồ thị có hướng trên cây phòng ban bằng truy vấn đệ quy CTE (`prevent_department_cycle`).
-- Cơ chế:
-- 1. Nếu `NEW.parent_id IS NULL` (nút gốc), cho phép ngay lập tức.
-- 2. Chặn tự tham chiếu trực tiếp (`NEW.parent_id = NEW.id`) với mã lỗi ràng buộc `23514` (`check_violation`).
-- 3. Sử dụng `WITH RECURSIVE descendants` duyệt lan truyền chiều rộng/sâu toàn bộ tập con cháu xuất phát từ `NEW.id`;
--    nếu `NEW.parent_id` xuất hiện trong tập `descendants`, nghĩa là phép gán tạo chu trình khép kín -> ném ngoại lệ `23514` hủy giao dịch.
CREATE OR REPLACE FUNCTION prevent_department_cycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.parent_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.id IS NOT NULL AND NEW.parent_id = NEW.id THEN
    RAISE EXCEPTION 'department cannot be its own parent' USING ERRCODE = '23514';
  END IF;
  -- Thuật toán: Duyệt đồ thị cây có hướng bằng CTE đệ quy (`WITH RECURSIVE`) tìm tập bao đóng bắc cầu các phòng ban con cháu
  IF NEW.id IS NOT NULL AND EXISTS (
    WITH RECURSIVE descendants AS (
      SELECT id FROM departments WHERE parent_id = NEW.id
      UNION ALL
      SELECT d.id FROM departments d JOIN descendants x ON d.parent_id = x.id
    )
    SELECT 1 FROM descendants WHERE id = NEW.parent_id
  ) THEN
    RAISE EXCEPTION 'department hierarchy cycle detected' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_department_cycle
BEFORE INSERT OR UPDATE OF parent_id ON departments
FOR EACH ROW EXECUTE FUNCTION prevent_department_cycle();
