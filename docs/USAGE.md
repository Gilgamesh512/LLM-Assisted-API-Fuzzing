# Hướng dẫn sử dụng — Nhiệm vụ B

## 0. Cài đặt

Deep Code CLI trong máy này **không lấy từ npm registry** — đã build trực tiếp
từ source code bạn tải về (`deepcode-cli-main/`) và `npm link` vào lệnh
`deepcode` toàn cục, để đảm bảo bạn luôn chạy đúng bản đã tinh chỉnh (có sẵn
skill `api-payload-generator`), không lệch phiên bản public.

```bash
# Chỉ cần làm lại khi build lỗi hoặc muốn refresh:
cd path/to/deepcode-cli-main
npm install        # cài dependency (tự chạy "npm run build" qua hook prepare)
cd packages/cli && npm link

# Python deps cho project Task B
cd ..
pip install -r requirements.txt
```

Sau khi sửa bất kỳ file nào trong `packages/` hoặc trong
`packages/core/templates/skills/bundled/` (kể cả skill
`api-payload-generator`), chạy `npm run build` ở root `deepcode-cli-main` để
rebuild — vì đã `npm link`, thay đổi có hiệu lực ngay cho lệnh `deepcode` toàn
cục, không cần link lại.

## 1. Cấu hình API key DeepSeek

Tạo `~/.deepcode/settings.json` (KHÔNG đặt trong repo — file này ở cấp user,
dùng chung cho mọi project):

```json
{
  "env": {
    "MODEL": "deepseek-v4-pro",
    "BASE_URL": "https://api.deepseek.com",
    "API_KEY": "sk-..."
  }
}
```

Lấy API key tại https://platform.deepseek.com/. Cấu hình `model`,
`thinkingEnabled`, `reasoningEffort` ở cấp project (`.deepcode/settings.json`,
đã có sẵn trong repo, không chứa key) sẽ override phần tương ứng của user
settings, còn `API_KEY` sẽ lấy từ user settings vì project settings không khai
báo lại.

## 2. Task B1 — Parse OpenAPI/Swagger

Input: file Swagger/OpenAPI của Thành viên A (crAPI, VAmPI — export từ
`/docs`, `/swagger.json`... của từng app đang chạy trong Docker).

```bash
python core/analyzer.py path/to/crapi_openapi.json -o context.json --pretty
```

Output `context.json` là mảng endpoint gọn — xem field trong
`core/analyzer.py` (method, path, parameters, authentication, jwt,
file_upload).

## 3. Task B2 & B3 — Sinh payload bằng Deep Code CLI + skill

Skill `api-payload-generator` là **built-in của CLI** (nhúng vào
`packages/core/templates/skills/bundled/`, xem
`../.deepcode/AGENTS.md`), nên có sẵn dù bạn chạy `deepcode` ở đâu — không chỉ
trong workspace root. Skill để `allow-implicit-invocation: false` nên phải
gọi thủ công bằng `/api-payload-generator` hoặc nêu rõ tên skill trong prompt.

```bash
cd <workspace-root>   # hoặc bất kỳ đâu — skill vẫn có sẵn
deepcode
```

Trong TUI, gõ `/api-payload-generator` để chọn skill, rồi dán nội dung
`context.json` (hoặc 1 vài endpoint) kèm yêu cầu, ví dụ:

```
Sinh payload bảo mật context-aware cho các endpoint sau (context.json):
<dán JSON ở đây>
```

Hoặc chạy không tương tác (phù hợp để script hoá pipeline):

```bash
deepcode -x -p "Dùng skill api-payload-generator, sinh payload bảo mật cho các endpoint trong context.json: $(cat context.json)" > raw_llm_output.txt
```

## 4. Task B4 — Validate output

```python
from pathlib import Path
from core.validator import validate_llm_output, payloads_to_jsonable
import json

raw = Path("raw_llm_output.txt").read_text(encoding="utf-8")
result = validate_llm_output(raw)

if result.ok:
    Path("payloads.json").write_text(
        json.dumps(payloads_to_jsonable(result.payloads), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"OK — {len(result.payloads)} payload hợp lệ, đã ghi payloads.json")
else:
    print("KHÔNG hợp lệ:", result.error_message)
    print("Repair prompt để gửi lại LLM:\n", result.repair_prompt)
```

`payloads.json` chính là sản phẩm bàn giao cho Thành viên C.

## 5. Vòng lặp tự sửa lỗi (khớp Task B4 + điều kiện dừng của Task C3)

Khi tích hợp thành pipeline tự động (việc của Thành viên C), lặp tối đa
`core.validator.MAX_REPAIR_ATTEMPTS` (= 3) lần: nếu `validate_llm_output`
trả `ok=False`, gửi `result.repair_prompt` lại cho `deepcode -x -p ...`, nhận
output mới, validate lại. Nếu vẫn thất bại sau 3 lần, ghi log lỗi và bỏ qua
endpoint đó thay vì lặp vô hạn.

## 6. Chạy test

```bash
python -m pytest tests/ -v
```
