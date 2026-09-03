# Test end-to-end pipeline thật — B1 → B2/B3 → B4 (Gemini)

Ngày chạy: 2026-08-22
Provider: Gemini (`gemini-2.5-flash`, qua endpoint tương thích OpenAI của Google — dùng để test miễn phí
trước khi có key DeepSeek chính thức, xem `scripts/switch_ai.py`)

## Bước 1 — B1: `core/analyzer.py`

```bash
python core/analyzer.py tests/fixtures/sample_openapi.json -o context.json --pretty
```

→ 4 endpoint (`POST /api/login`, `GET /api/products/{id}`, `POST /api/users/avatar`, `GET /api/users/{id}`).
File: [`docs/evidence/context_sample_openapi.json`](evidence/context_sample_openapi.json).

## Bước 2 — B2/B3: skill `api-payload-generator` qua `deepcode` (chạy thật, không giả lập)

```bash
deepcode -x -p "Gọi tool 'skill' với tên 'api-payload-generator' ngay bây giờ để nạp hướng dẫn của skill đó. Sau đó đọc file context.json và làm đúng theo hướng dẫn skill vừa nạp để sinh payload bảo mật cho các endpoint trong file, trả về JSON array theo đúng schema."
```

→ Output đầy đủ: [`docs/evidence/deepcode_gemini_run_log.txt`](evidence/deepcode_gemini_run_log.txt) (8 payload, JSON array hợp lệ).

## Bước 3 — B4: `core/validator.py`

```python
from core.validator import validate_llm_output
result = validate_llm_output(open("deepcode_gemini_run_log.txt", encoding="utf-8").read())
# result.ok == True, len(result.payloads) == 8
```

**Kết quả**: `ok: True` — **8/8 payload hợp lệ 100%** theo schema `AttackPayload`.

| Vulnerability type | Method | Path | Param |
|---|---|---|---|
| SQLi | POST | /api/login | username |
| SQLi | POST | /api/login | password |
| BOLA | GET | /api/products/{id} | id |
| Other | GET | /api/products/{id} | verbose |
| FileUpload | POST | /api/users/avatar | file |
| FileUpload | POST | /api/users/avatar | file |
| BOLA | GET | /api/users/{id} | id |
| JWT/Auth | GET | /api/users/{id} | Authorization |

Model tự chọn đúng nhóm lỗ hổng theo ngữ cảnh (không máy móc): `id` kiểu path + JWT → BOLA;
`username`/`password` string trong body của endpoint login → SQLi; `file` + JWT → FileUpload;
JWT có mặt → thêm test case `alg=none`. Đúng đúng tinh thần "context-aware" mà đề tài hướng tới.

## Bug phát hiện & sửa trong lúc chạy thật (không phải bug giả lập)

Chạy trực tiếp qua `deepcode` (khác với 2 script test độc lập `deepseek_client.py`/`gemini_client.py`)
mới lộ ra 1 bug thật trong chính mã nguồn CLI: mọi request luôn gửi kèm field `"thinking": {...}` —
phần mở rộng riêng của DeepSeek trên chuẩn OpenAI chat completions — bất kể provider nào đang được gọi.
Endpoint tương thích OpenAI của Gemini validate request nghiêm ngặt hơn, từ chối thẳng field lạ này →
`HTTP 400: 400 status code (no body)`, không có traceback rõ ràng (phải bật `debugLogEnabled` mới thấy
request/response thật trong `~/.deepcode/logs/debug.log`).

Đã sửa `packages/core/src/common/openai-thinking.ts::buildThinkingRequestOptions` — chỉ bỏ qua field
`thinking` khi `baseURL` khớp 1 provider trong `EXTRA_MODEL_PROVIDERS` (hiện tại: Gemini), giữ nguyên
hành vi cho DeepSeek và mọi endpoint tương thích OpenAI khác (ví dụ Coding Plan). 2 test mới +
`npm run check && npm test` sạch toàn bộ 3 package trước khi build lại.

**Ghi chú cho báo cáo khoa học**: đây cũng là minh chứng thực nghiệm cho đúng luận điểm mà README của
`deepcode-cli` trích dẫn ("Better Models, Worse Tools" — Armin Ronacher) — 1 harness tối ưu riêng cho
1 model có thể không tương thích ngay với model khác dù cùng chuẩn API, cần điều chỉnh tool schema theo
từng nhà cung cấp.
