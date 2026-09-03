# Kiểm tra toàn diện hệ thống — 23/08/2026

Kiểm tra lại toàn bộ repo `deepcode-cli-main` (đã merge `LLM-API-Fuzzer` vào làm subtree) trước deadline
nội bộ nhóm. Mục tiêu: xác nhận cái gì đang chạy tốt, liệt kê chính xác lỗi/việc còn lại kèm vị trí file
để người nhận sửa được ngay, không phải dò lại từ đầu.

## 1. Test & build — tất cả xanh (đã chạy thật, không suy đoán)

| Hạng mục | Lệnh | Kết quả |
|---|---|---|
| Python (LLM-API-Fuzzer) | `pytest tests/ -q` | **41/41 pass** |
| TypeScript — 3 workspace (cli/core/vscode) | `npm test` | **653/662 pass, 0 fail** (9 skip có chủ đích) |
| Typecheck | `npm run typecheck` | 0 lỗi |
| Lint | `npm run lint` | 0 lỗi, **1 warning** (mục 3.3 dưới) |
| Format | `npm run format:check` | Sạch |

## 2. Bảo mật / secrets — sạch, đã xác minh lại toàn bộ lịch sử git

- `git log -p --all -- LLM-API-Fuzzer/.env*` + quét toàn repo (`git grep`) cho pattern key Gemini/DeepSeek:
  **không tìm thấy key thật nào trong lịch sử commit** — vụ rò rỉ `.env.txt` trước đây đã được purge sạch
  (không phải chỉ xoá ở commit mới, đã kiểm tra lại từ đầu).
- `.gitignore` đang chặn đúng: `.env`, `.env.*`, `*.env`, `.deepcode/settings.local.json`.
- `.deepcode/settings.json` (file có commit) chỉ chứa `MODEL`/`BASE_URL` non-secret, không có key.

## 3. Lỗi/việc còn lại cần sửa — có vị trí cụ thể

### 3.1 [ĐÃ SỬA — 23/08/2026] Command injection ở `scripts/run_pipeline.py`

**File**: `LLM-API-Fuzzer/scripts/run_pipeline.py`, hàm `run_deepcode()`. Trước đây gọi:

```python
subprocess.run(["deepcode", "-x", "-p", prompt], shell=True, ...)
```

Comment cũ trong code ghi "Python tự escape khi truyền list cho subprocess với shell=True" — **đúng một
nửa**: cách này chỉ escape đúng cho việc tách argv (CommandLineToArgvW), nhưng trên Windows `shell=True`
vẫn đẩy toàn bộ chuỗi lệnh qua `cmd.exe`, và cmd.exe tự diễn giải `&`, `|`, `<`, `>`, `^`, `%` **kể cả khi
nằm trong ngoặc kép**. Đường sửa lỗi (`run_b2_b3_repair`) nhúng thẳng output thô của LLM — chính là các
payload tấn công (SQLi, OS command injection...) mà tool tự sinh ra — vào chuỗi lệnh đó, không sanitize.
4 test cũ của `run_pipeline.py` đều mock `run_deepcode()` hoàn toàn nên đường này chưa từng chạy thật.

**Đã sửa** (fix tận gốc, không phải chỉ né): thêm `_resolve_deepcode_entry()` — tự tìm shim
`deepcode`/`deepcode.cmd` qua `shutil.which`, từ đó suy ra file `cli.js` thật của package
(`<thư mục shim>/node_modules/@vegamo/deepcode-cli/dist/cli.js` — đúng cấu trúc mà chính shim npm dùng,
không hardcode đường dẫn riêng của máy nào). `run_deepcode()` giờ gọi thẳng
`subprocess.run([node_path, cli_js, "-x", "-p", prompt], shell=False, ...)` — **không còn đi qua
cmd.exe nữa**, nên ký tự shell trong prompt (dù prompt chứa nguyên văn payload injection) chỉ còn là text
thuần, không có đường nào để bị diễn giải thành lệnh.

**Verify thật** (không chỉ suy luận): gọi `run_deepcode()` với prompt chèn
`& echo INJECTED > injection_proof.txt & whoami | echo also_injected` — deepcode (Gemini) trả lời "OK"
(coi toàn bộ là text), **không có file `injection_proof.txt` nào được tạo ra** → xác nhận không còn
command injection. `pytest tests/ -q` chạy lại sau khi sửa: **41/41 pass** (test cũ mock `run_deepcode`
nên không cần sửa gì thêm).

### 3.2 [Việc còn lại đã biết từ trước, vẫn còn mở]

1. **Key DeepSeek thật** — `.env` hiện chỉ có `GEMINI_API_KEY`, chưa có `DEEPSEEK_API_KEY`. Đây vẫn là gap
   duy nhất cho yêu cầu "log test mẫu" của kế hoạch (mục 2). Một khi có key: `python scripts/switch_ai.py
   deepseek` rồi chạy lại `run_pipeline.py` là xong, code đã sẵn sàng.
2. **`analyzer.py` (B1)** mới test trên 1 fixture mẫu (4 endpoint) — chưa chạy trên spec thật của
   crAPI/DVGA/VAmPI (chờ Member A dựng Docker xong).
3. **Chưa push GitHub** — repo hiện chỉ có local, `git remote -v` rỗng, máy này chưa cài `gh` CLI. Cần
   quyết định: repo cá nhân hay của nhóm, public hay private, rồi `gh auth login` hoặc set up SSH/PAT.

### 3.3 Việc nhỏ, không chặn deadline

- ESLint warning: `scripts/copy-bundle-assets.js:1` — import `statSync` không dùng tới. Xoá import là xong.
- File `cơ chế đổi AI.txt` ở gốc repo đang **untracked** (không commit, cũng không bị gitignore) — là ghi
  chú cá nhân hướng dẫn đổi AI, nên quyết định dứt khoát: commit vào `docs/` hoặc thêm vào `.gitignore`,
  đừng để lửng.

## 4. Tóm tắt cho người sửa

**Cập nhật 23/08/2026, sau khi vá**: mục 3.1 (command injection qua `shell=True`) **đã sửa xong và verify
thật** — không còn việc bắt buộc nào chặn trước khi dùng pipeline với payload thật.
Việc đang chờ input từ bên ngoài, không phải bug: **mục 3.2** (key DeepSeek, spec thật, remote GitHub).
Còn lại là dọn dẹp nhỏ (mục 3.3), làm lúc nào cũng được.
