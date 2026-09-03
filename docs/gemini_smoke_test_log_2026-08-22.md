# Log test mẫu — Gemini (`core/gemini_client.py --smoke-test`)

Ngày chạy: 2026-08-22
Model: `gemini-flash-lite-latest` (endpoint native `generateContent`, không phải endpoint OpenAI-compat dùng cho `deepcode` CLI)
Mục đích: xác nhận pipeline gọi API + parse response hoạt động đúng, trước khi có key DeepSeek chính thức.

## Request mẫu 1/2

**Prompt**: `Trả lời đúng một câu: bạn là mô hình nào?`

**Reply**: `Tôi là Gemini, một mô hình ngôn ngữ lớn được phát triển bởi Google.`

Latency: 1.141s | Usage: `{promptTokenCount: 12, candidatesTokenCount: 16, totalTokenCount: 28}`

## Request mẫu 2/2

**Prompt**: `Đây là 1 endpoint API: {"method": "GET", "path": "/api/users/{id}", "jwt": true}. Hãy nêu ngắn gọn 1 loại lỗ hổng cần kiểm thử cho endpoint này, không vượt quá 1 câu.`

**Reply**: `Loại lỗ hổng cần kiểm thử là **BOLA (Broken Object Level Authorization)**, nhằm kiểm tra xem một người dùng đã xác thực có thể truy cập hoặc chỉnh sửa thông tin của người dùng khác bằng cách thay đổi giá trị {id} trên URL hay không.`

Latency: 1.219s | Usage: `{promptTokenCount: 52, candidatesTokenCount: 56, totalTokenCount: 108}`

## Kết luận

`[gemini_client] Smoke test THÀNH CÔNG — API key hoạt động, kết nối Gemini OK.`

Model xác định đúng BOLA cho endpoint `GET /api/users/{id}` với `jwt: true` — đúng logic mà skill
`api-payload-generator` mong đợi (tham số `id` kiểu path + có auth → cân nhắc BOLA/IDOR). Bằng chứng
pipeline (gọi API → parse response) hoạt động đúng ở mức cơ bản; bước tiếp theo là chạy chính skill qua
`deepcode` (xem `scripts/switch_ai.py gemini`) trên bộ endpoint đầy đủ từ `tests/fixtures/sample_openapi.json`.

Log tương đương cho DeepSeek (`core/deepseek_client.py --smoke-test`) — bằng chứng bắt buộc cho Task 2
chính thức — sẽ được thêm khi có API key DeepSeek thật.
