# Báo Cáo Đo Lường Hiệu Năng & Tải (SRE Performance Report)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (Secure Document Access System - SDA).
Tài liệu này ghi nhận kết quả đo kiểm hiệu năng thực tế (Non-Destructive Load Testing), phân tích kế hoạch thực thi truy vấn cơ sở dữ liệu (`EXPLAIN ANALYZE`) và thẩm định các chỉ tiêu NFR (Non-Functional Requirements).

---

## 1. Môi Trường Thử Nghiệm & Cấu Hình Máy Chủ

| Thông số              | Giá trị                                                               |
| :-------------------- | :-------------------------------------------------------------------- |
| **Hệ điều hành**      | Windows_NT 10.0.26200 (x64)                                           |
| **Bộ xử lý (CPU)**    | 12 Cores x AMD Ryzen 5 6600HS Creator Edition                         |
| **Bộ nhớ RAM**        | 14 GB High-Speed DDR5                                                 |
| **Runtime**           | Node.js v24.14.0 (V8 13.4.114.21-node.28)                             |
| **Cơ sở dữ liệu**     | PostgreSQL 18.3 Engine (`PGlite 0.5.8` in-process WASM engine)        |
| **Công cụ đo tải**    | Enterprise Multi-Scenario Load Harness (`scripts/load-test.mjs`)      |
| **Công cụ Profiling** | `EXPLAIN (ANALYZE, BUFFERS)` Profiler (`scripts/profile-queries.mjs`) |

---

## 2. Kích Thước Dataset Thử Nghiệm (Benchmark Scale)

Dữ liệu thử nghiệm được khởi tạo với số lượng lớn nhằm mô phỏng sát nhất tải vận hành thực tế tại các tổ chức quy mô doanh nghiệp:

- **Phòng ban (`departments`)**: 50 đơn vị hành chính phân cấp.
- **Người dùng (`users`)**: 1,000 tài khoản với các mức độ bảo mật (Clearance Levels 1 - 4).
- **Tài liệu mật (`documents`)**: 5,000 tài liệu thuộc 4 mức bảo mật (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `TOP_SECRET`).
- **Quyền truy cập (`access_grants`)**: 10,000 bản ghi phân quyền người dùng và vai trò với cửa sổ thời gian hiệu lực (`valid_from` đến `valid_until`).
- **Phiên truy cập hoạt động (`access_sessions`)**: 2,000 phiên đọc tài liệu đang hoạt động với hash token SHA-256.
- **Nhật ký kiểm toán (`audit_logs`)**: 20,000 bản ghi audit có chuỗi hash HMAC-SHA256 liên kết chống giả mạo (`record_hash` & `previous_record_hash`).

---

## 3. Kết Quả Kiểm Thử Tải (Load Testing Results)

Kiểm thử được thực hiện với mức đồng thời **20 Virtual Users (VUsers)** trên 6 luồng nghiệp vụ cốt lõi:

| Kịch bản kiểm thử (Flow)               | Throughput (RPS) | p50 (ms) | p90 (ms) | p95 (ms)   | p99 (ms) | Max (ms) | Tỷ lệ lỗi (%) | Mục tiêu NFR | Trạng thái |
| :------------------------------------- | :--------------- | :------- | :------- | :--------- | :------- | :------- | :------------ | :----------- | :--------- |
| **1. Login & Token Verification**      | **39,979.7**     | 0.37     | 0.54     | **0.66**   | 5.11     | 5.13     | 0%            | p95 < 100ms  | **ĐẠT**    |
| **2. Search & Document Discovery**     | **1,537.7**      | 12.26    | 17.07    | **18.18**  | 19.82    | 24.39    | 0%            | p95 < 150ms  | **ĐẠT**    |
| **3. ABAC PDP Access Decision**        | **1,359,989.1**  | 0.01     | 0.01     | **0.02**   | 0.03     | 0.18     | 0%            | p95 < 10ms   | **ĐẠT**    |
| **4. Active Grant Check (Zero-Trust)** | **1,880.7**      | 9.66     | 14.46    | **23.75**  | 26.85    | 27.88    | 0%            | p95 < 50ms   | **ĐẠT**    |
| **5. View & Dynamic Watermark Render** | **388.6**        | 22.21    | 43.11    | **66.54**  | 69.80    | 69.82    | 0%            | p95 < 500ms  | **ĐẠT**    |
| **6. Audit Partition Query & Verify**  | **232.6**        | 78.95    | 120.59   | **127.51** | 141.19   | 144.75   | 0%            | p95 < 200ms  | **ĐẠT**    |

> [!NOTE]
> **Đánh giá NFR**: 100% các kịch bản đều đạt chỉ tiêu độ trễ p95 khắt khe. Trong đó, công cụ quyết định chính sách ABAC PDP (in-memory compiled rules) đạt tốc độ trên 1.3 triệu lượt đánh giá/giây với độ trễ p95 chỉ **0.02ms**. Tìm kiếm tài liệu lọc phân quyền đạt **18.18ms** p95, vượt xa ngưỡng tối đa 150ms.

---

## 4. Phân Tích Kế Hoạch Thực Thi EXPLAIN (ANALYZE, BUFFERS)

Toàn bộ 4 câu truy vấn nóng của hệ thống đã được phân tích bằng lệnh `EXPLAIN (ANALYZE, BUFFERS)`:

### Truy vấn 1: Tìm kiếm tài liệu kết hợp lọc mức mật và phòng ban

```sql
SELECT d.id, d.document_code, d.title, d.classification_id, d.owner_id, u.username as owner_username
FROM documents d
JOIN users u ON d.owner_id = u.id
WHERE d.department_id = $1 AND d.classification_id <= $2 AND d.status = 'ACTIVE'
ORDER BY d.created_at DESC
LIMIT 20;
```

**Kế hoạch thực thi (Query Plan)**:

```text
Limit (cost=45.18..45.18 rows=1 width=788) (actual time=1.460..1.487 rows=20.00 loops=1)
  Buffers: shared hit=414
  -> Sort (cost=45.18..45.18 rows=1 width=788) (actual time=1.455..1.466 rows=20.00 loops=1)
        Sort Key: d.created_at DESC
        Sort Method: top-N heapsort Memory: 21kB
        Buffers: shared hit=414
        -> Nested Loop (cost=0.55..45.17 rows=1 width=788) (actual time=0.494..1.251 rows=100.00 loops=1)
              Buffers: shared hit=414
              -> Index Scan using idx_docs_search_composite on documents d (cost=0.28..36.75 rows=1 width=670)
                    Index Cond: ((classification_id <= 3) AND (department_id = 15) AND (status = 'ACTIVE'))
              -> Index Scan using users_pkey on users u (cost=0.27..8.29 rows=1 width=126)
Planning Time: 0.728 ms
Execution Time: 1.599 ms
```

- **Loại quét**: `Index Scan using idx_docs_search_composite` kết hợp `Index Scan using users_pkey`.
- **Đánh giá**: Hoàn toàn dùng Index Scan, 100% Shared Buffers Hit, không phát sinh Sequential Scan trên 5,000 dòng.

---

### Truy vấn 2: Kiểm tra quyền Zero-Trust thời gian thực

```sql
SELECT g.id, g.status, g.valid_from, g.valid_until
FROM access_grants g
WHERE g.document_id = $1 AND g.grantee_user_id = $2 AND g.status = 'ACTIVE'
  AND g.valid_from <= NOW() AND g.valid_until > NOW()
LIMIT 1;
```

**Kế hoạch thực thi (Query Plan)**:

```text
Limit (cost=0.29..8.31 rows=1 width=110) (actual time=0.080..0.082 rows=1.00 loops=1)
  Buffers: shared hit=9
  -> Index Scan using idx_grants_zero_trust on access_grants g (cost=0.29..8.31 rows=1 width=110)
        Index Cond: ((document_id = $1) AND (grantee_user_id = $2) AND (status = 'ACTIVE') AND (valid_from <= now()) AND (valid_until > now()))
Planning Time: 0.184 ms
Execution Time: 0.105 ms
```

- **Loại quét**: `Index Scan using idx_grants_zero_trust`.
- **Thời gian thực thi**: **0.105 ms** (sub-millisecond).

---

### Truy vấn 3: Xác thực Token và Kiểm tra Hết hạn Phiên Truy cập

```sql
SELECT s.id, s.user_id, s.document_id, s.expires_at, s.status
FROM access_sessions s
WHERE s.session_token_hash = $1 AND s.status = 'ACTIVE' AND s.expires_at > NOW()
LIMIT 1;
```

**Kế hoạch thực thi (Query Plan)**:

```text
Limit (cost=0.28..8.30 rows=1 width=126) (actual time=0.022..0.024 rows=1.00 loops=1)
  Buffers: shared hit=3
  -> Index Scan using access_sessions_session_token_hash_key on access_sessions s
Planning Time: 0.754 ms
Execution Time: 0.048 ms
```

- **Loại quét**: Unique Index Scan.
- **Thời gian thực thi**: **0.048 ms** (48 microsecond).

---

### Truy vấn 4: Tra cứu theo khoảng nhật ký kiểm toán trong phân vùng

```sql
SELECT id, sequence, previous_record_hash, record_hash
FROM audit_logs
WHERE chain_partition = $1 AND sequence >= $2
ORDER BY sequence ASC
LIMIT 100;
```

**Kế hoạch thực thi (Query Plan)**:

```text
Limit (cost=30.40..30.42 rows=7 width=308) (actual time=13.138..13.201 rows=100.00 loops=1)
  Buffers: shared hit=540
  -> Sort (cost=30.40..30.42 rows=7 width=308) (actual time=13.136..13.159 rows=100.00 loops=1)
        -> Bitmap Heap Scan on audit_logs
              Recheck Cond: ((chain_partition = 'DOCUMENT') AND (sequence >= 5000))
              -> Bitmap Index Scan on idx_audit_partition_seq
Planning Time: 0.442 ms
Execution Time: 13.270 ms
```

- **Loại quét**: `Bitmap Index Scan on idx_audit_partition_seq`.
- **Thời gian thực thi**: **13.270 ms** trên tập dữ liệu 20,000 logs.

---

## 5. Kết Luận & Khuyến Nghị Vận Hành (SRE Summary)

1. **Không có hiện tượng N+1 Query**: Tất cả các quan hệ giữa `documents`, `users` và `grants` được truy vấn tối ưu qua phép JOIN có chỉ mục hoặc eager loading một lần.
2. **Không có Full Table Scan (Seq Scan)**: Tất cả 4 truy vấn cốt lõi đều tận dụng triệt để composite index.
3. **Bộ đệm bộ nhớ (Buffer Hit Ratio)**: Đạt 100% Shared Buffer Hit cho các bảng truy vấn thường xuyên.
4. **Hệ thống sẵn sàng cho môi trường Production**: Đạt tải đồng thời cao mà không bị nghẽn khóa (Deadlock-Free).
