# AGENTS.md — LLM-API-Fuzzer (Nhiệm vụ B)

Đây là workspace của đề tài NCKH "Ứng dụng LLM trong sinh tự động test case
kiểm thử bảo mật API REST" — phạm vi của pipeline Python ở workspace root là
**Nhiệm vụ B (Module đọc API & Thiết kế Prompt LLM)**. `Aegis Agent/` là repo
DeepCode CLI/VS Code companion dùng để chạy skill, không phải bản sao của
pipeline Python.

## Phạm vi & mục tiêu

- `core/analyzer.py` (Task B1): parse OpenAPI/Swagger → JSON gọn.
- Task B2 & B3 (system prompt LLM đóng vai chuyên gia bảo mật, sinh
  payload context-aware) đã được nhúng
  thành skill built-in của chính CLI (`api-payload-generator`), sống ở
  `../packages/core/templates/skills/bundled/api-payload-generator/SKILL.md`
  trong `Aegis Agent`. Vì `deepcode` được build từ source này,
  đúng source đó, skill có sẵn ở bất kỳ project nào, không riêng thư mục này.
  Sửa skill → chạy `npm run build` ở root `deepcode-cli-main` để rebuild.
- `core/validator.py` (Task B4): Pydantic guardrails xác thực JSON trả về từ LLM,
  schema phải khớp 100% với output schema khai báo trong SKILL.md nói trên.
- Output cuối cùng của thư mục này (list `AttackPayload` đã validate) được bàn
  giao cho Thành viên C (fuzzing engine + vòng phản hồi runtime).

## Mục tiêu benchmark

Các endpoint được phân tích/sinh payload chỉ thuộc về **OWASP crAPI, DVGA,
VAmPI** — các ứng dụng cố ý có lỗ hổng, chạy cục bộ trong Docker do Thành viên A
dựng, dùng riêng cho nghiên cứu. Không nhắm mục tiêu ngoài phạm vi này.

## Quy ước code

- Python 3.11+, type hint đầy đủ, không dùng biến toàn cục ẩn.
- Không tự ý "khẳng định" một endpoint có lỗ hổng — luôn diễn đạt ở dạng "test
  case cần thử" / "potential", trừ khi có bằng chứng runtime từ Thành viên C.
- Không hardcode API key trong bất kỳ file nào commit vào git. API key Gemini
  đặt ở `~/.deepcode/settings.json` (user-level, không nằm trong repo).
- Khi sửa `core/validator.py`, giữ nguyên field bắt buộc của `AttackPayload` trừ
  khi cả 3 thành viên B/C/D đã thống nhất đổi schema (vì C và D phụ thuộc trực
  tiếp vào định dạng này).

## Test

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Chạy pipeline thủ công

```bash
python core/analyzer.py path/to/swagger.yaml -o context.json
deepcode -p "Dùng skill api-payload-generator, sinh payload bảo mật cho các endpoint trong context.json"
```

Xem chi tiết đầy đủ ở [docs/USAGE.md](docs/USAGE.md).
