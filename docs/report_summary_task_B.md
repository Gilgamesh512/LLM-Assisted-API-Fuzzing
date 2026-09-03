# Mô tả ngắn gọn nhiệm vụ B (dùng cho báo cáo)

Người B chịu trách nhiệm xây dựng **"bộ não"** của hệ thống: module đọc và chuẩn hoá tài liệu API
(OpenAPI 3.x/Swagger 2.0, JSON/YAML) thành JSON gọn — trích xuất endpoint, HTTP method, tham số, kiểu dữ
liệu, authentication/JWT, và khả năng file upload, không suy đoán lỗ hổng ở bước này. Từ JSON gọn đó,
Người B thiết kế skill/prompt để LLM (DeepSeek theo kế hoạch chính thức; Gemini dùng song song để thử
nghiệm miễn phí trước khi có key DeepSeek) đóng vai chuyên gia bảo mật, sinh payload tấn công có cấu trúc
phù hợp ngữ cảnh từng endpoint (SQLi, BOLA/IDOR, SSRF, JWT/Auth, FileUpload) thay vì áp payload cố định.
Cuối cùng, Người B xây dựng lớp **JSON Guardrails** (Pydantic) đảm bảo 100% payload trước khi bàn giao cho
Thành viên C đều đúng cấu trúc `AttackPayload`, kèm cơ chế tự sửa lỗi khi LLM trả sai định dạng (tự động
sinh lại, tối đa 3 lần) trước khi báo lỗi.

Toàn bộ pipeline (parse → sinh payload → validate) đã được kiểm chứng chạy thật end-to-end qua chính CLI
`deepcode` (không phải giả lập) trên bộ 4 endpoint mẫu, đạt **8/8 payload hợp lệ**, tự động chọn đúng
nhóm lỗ hổng theo ngữ cảnh (kiểu dữ liệu, vị trí tham số, có auth/JWT hay không). Xây thêm cơ chế đổi qua
lại giữa 2 nhà cung cấp LLM (DeepSeek/Gemini) chỉ bằng 1 lệnh, và 1 script gộp toàn bộ 3 bước
(`scripts/run_pipeline.py`) thành 1 lệnh duy nhất cho Thành viên C dễ tích hợp.

## Kết quả đạt được

| Hạng mục | Trạng thái |
|---|---|
| `core/analyzer.py` — parse OpenAPI/Swagger → JSON gọn | ✅ Hoàn thành, có test |
| `api-payload-generator` skill — sinh payload context-aware | ✅ Hoàn thành, chạy thật end-to-end |
| `core/validator.py` — JSON Guardrails + repair-loop | ✅ Hoàn thành, có test |
| `scripts/run_pipeline.py` — gộp cả pipeline 1 lệnh | ✅ Hoàn thành, có test (mock) |
| `scripts/switch_ai.py` — đổi provider DeepSeek/Gemini | ✅ Hoàn thành, verify thật |
| Kết nối DeepSeek API + log test mẫu | ⏳ Chờ API key DeepSeek |

**41 test tự động, tất cả pass** (`pytest tests/ -v`).
