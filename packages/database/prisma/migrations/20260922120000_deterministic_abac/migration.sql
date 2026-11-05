-- Thuật toán tổng quan migration:
-- Thiết lập cơ chế kiểm soát đồng thời lạc quan (Optimistic Concurrency Control - OCC) và vô hiệu hóa bộ nhớ đệm chính sách ABAC tất định:
-- 1. Cấp phát số hiệu phiên bản đơn điệu toàn cục qua sequence không quay vòng `abac_policy_version_seq`.
-- 2. Ràng buộc kiểu dữ liệu JSONB cho trường nghĩa vụ hậu kiểm `obligations` bắt buộc là mảng (`jsonb_typeof(obligations) = 'array'`).
-- 3. Tự động tăng `version` khi nội dung thực chất của bảng cha thay đổi và lan truyền tăng `version` ngược từ bảng con (`attribute_options`, `policy_rule_conditions`) lên bảng cha.
CREATE SEQUENCE abac_policy_version_seq AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE;

ALTER TABLE attribute_definitions
  ADD COLUMN version BIGINT NOT NULL DEFAULT nextval('abac_policy_version_seq');

-- Thuật toán: Ràng buộc cấu trúc mảng JSONB (`ck_policy_rule_obligations_array`) đảm bảo trình thực thi PDP/PEP luôn đọc `obligations` như danh sách nghĩa vụ tất định.
ALTER TABLE policy_rules
  ADD COLUMN obligations JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN version BIGINT NOT NULL DEFAULT nextval('abac_policy_version_seq'),
  ADD CONSTRAINT ck_policy_rule_obligations_array CHECK (jsonb_typeof(obligations) = 'array');

-- Thuật toán: Tự động tăng đơn điệu phiên bản hàng chính sách ABAC (`bump_abac_row_version` - Monotonic OCC Version Bump).
-- Cơ chế:
-- - Khi `DELETE`: nhảy nhịp sequence toàn cục `abac_policy_version_seq` để đánh dấu tập chính sách đã biến đổi đối với bộ nhớ đệm PDP.
-- - Khi `UPDATE`: so sánh ảnh JSONB của `NEW` và `OLD` sau khi loại trừ hai trường siêu dữ liệu `updated_at` và `version`;
--   chỉ cấp số `version` mới từ sequence nếu dữ liệu nghiệp vụ thực sự thay đổi hoặc `version` bị tác động trực tiếp.
CREATE OR REPLACE FUNCTION bump_abac_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM nextval('abac_policy_version_seq');
    RETURN OLD;
  END IF;
  IF NEW.version IS DISTINCT FROM OLD.version
    OR (to_jsonb(NEW) - 'updated_at' - 'version')
      IS DISTINCT FROM (to_jsonb(OLD) - 'updated_at' - 'version') THEN
    NEW.version := nextval('abac_policy_version_seq');
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_attribute_definitions_version
BEFORE UPDATE OR DELETE ON attribute_definitions
FOR EACH ROW EXECUTE FUNCTION bump_abac_row_version();

CREATE TRIGGER trg_policy_rules_version
BEFORE UPDATE OR DELETE ON policy_rules
FOR EACH ROW EXECUTE FUNCTION bump_abac_row_version();

-- Thuật toán: Lan truyền tăng phiên bản từ thực thể con lên thực thể gốc tổng hợp (`bump_abac_parent_version` - Aggregate Root Version Propagation).
-- Cơ chế:
-- - Bỏ qua các lệnh `UPDATE` rỗng (`to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD)`).
-- - Khi thêm/sửa/xóa dòng con trên `attribute_options` hoặc `policy_rule_conditions`, tự động cập nhật `version = nextval('abac_policy_version_seq')`
--   cho bản ghi cha tương ứng trên `attribute_definitions` hoặc `policy_rules` (và cập nhật cả cha cũ lẫn cha mới nếu khóa ngoại bị chuyển đổi),
--   bảo đảm xung đột ghi đồng thời trên điều kiện con luôn bị phát hiện qua `version` của cha.
CREATE OR REPLACE FUNCTION bump_abac_parent_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  parent_id BIGINT;
BEGIN
  IF TG_OP = 'UPDATE' AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'attribute_options' THEN
    IF TG_OP = 'UPDATE' AND OLD.attribute_definition_id <> NEW.attribute_definition_id THEN
      UPDATE attribute_definitions
      SET version = nextval('abac_policy_version_seq')
      WHERE id = OLD.attribute_definition_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.attribute_definition_id ELSE NEW.attribute_definition_id END;
    UPDATE attribute_definitions
    SET version = nextval('abac_policy_version_seq')
    WHERE id = parent_id;
  ELSE
    IF TG_OP = 'UPDATE' AND OLD.policy_rule_id <> NEW.policy_rule_id THEN
      UPDATE policy_rules
      SET version = nextval('abac_policy_version_seq')
      WHERE id = OLD.policy_rule_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.policy_rule_id ELSE NEW.policy_rule_id END;
    UPDATE policy_rules
    SET version = nextval('abac_policy_version_seq')
    WHERE id = parent_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_attribute_options_version
AFTER INSERT OR UPDATE OR DELETE ON attribute_options
FOR EACH ROW EXECUTE FUNCTION bump_abac_parent_version();

CREATE TRIGGER trg_policy_rule_conditions_version
AFTER INSERT OR UPDATE OR DELETE ON policy_rule_conditions
FOR EACH ROW EXECUTE FUNCTION bump_abac_parent_version();
