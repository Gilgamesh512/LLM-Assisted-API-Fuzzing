# LLM-API-Fuzzer — Kiểm thử bảo mật API REST bằng fuzzing có LLM hỗ trợ

## 1. Kiến trúc & luồng chạy

```
        A. TARGET LAB (Docker)              B. SINH PAYLOAD (LLM)            C. FUZZING              TỔNG HỢP
   ┌────────────────────────────┐   ┌──────────────────────────────┐  ┌───────────────────┐  ┌────────────────────┐
   │ VAmPI  :5002 (REST)        │   │ core/analyzer.py  (đọc spec)  │  │ Schemathesis      │  │ scripts/           │
   │ crAPI  :8888 (REST)        │◄──┤ core/gemini_client.py (LLM)   ├─►│  (REST + GraphQL) ├─►│  aggregate_results │
   │ DVGA   :5013 (GraphQL)     │   │ scripts/gen_payloads.py       │  │ Nuclei (template) │  │  -> 1 báo cáo gộp  │
   └────────────────────────────┘   │  -> 4 file payload đúng format│  └───────────────────┘  └────────────────────┘
     lab/lab.sh up                   └──────────────────────────────┘
```

**4 file payload** (B sinh, C ăn vào) — đúng và chỉ 4 file này:

| File | Target | Tool đọc |
|---|---|---|
| `Schemathesis/payload_rest.json` | VAmPI | Schemathesis REST |
| `Schemathesis/payload_crapi.json` | crAPI | Schemathesis REST |
| `Schemathesis/payload_graphql.json` | DVGA | Schemathesis GraphQL |
| `Nuclei/executor/benchmark/suite.json` | VAmPI | Nuclei |

---

## 2. Yêu cầu môi trường

| Thành phần | Ghi chú |
|---|---|
| **OS** | **Linux khuyến nghị** (target lab là Docker Linux; script auth/lab viết cho bash) |
| **Python** | **3.11 – 3.13**. KHÔNG dùng 3.14 (schemathesis/pydantic-core chưa có wheel cho 3.14) |
| **Docker** + compose plugin | Chỉ để chạy target lab. Bản thân fuzzer không cần Docker |
| **nuclei binary** | Tải từ https://github.com/projectdiscovery/nuclei/releases, đưa vào PATH |
| **Gemini API key** | Đặt trong `.env` (xem dưới). Provider đổi được sang DeepSeek qua `scripts/switch_ai.py` |

---

## 3. Cài đặt

```bash
git clone <repo> && cd LLM-API-Fuzzer-main

# 3.1 API key — .env KHÔNG theo git, phải tạo lại mỗi máy
echo 'GEMINI_API_KEY=<key-cua-ban>' > .env

# 3.2 Python deps (gộp cả B và C)
pip install -r requirements.txt                 # pydantic, pyyaml, requests, pytest
pip install -r Schemathesis/requirements.txt    # schemathesis, httpx 

# 3.3 nuclei binary (Linux) — ví dụ:
#   wget .../nuclei_x.y.z_linux_amd64.zip && unzip && sudo mv nuclei /usr/local/bin/
nuclei -version
```

---

## 4. Chạy đầy đủ từ đầu đến cuối

```bash
# BƯỚC A — dựng 3 target (kéo image, init DB VAmPI, tự tải compose crAPI)
bash lab/lab.sh up
bash lab/lab.sh status         

# BƯỚC B — LLM sinh 4 file payload đúng định dạng
python scripts/gen_payloads.py

# Lấy token xác thực từ target đang chạy (-> Schemathesis/tokens.env)
python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py

# BƯỚC C1 — Schemathesis (REST vampi+crapi, GraphQL dvga)
python Schemathesis/run_security_tests.py

# BƯỚC C2 — Nuclei (dùng suite.json B vừa sinh; JWT= inject token thật cho endpoint auth)
cd Nuclei/executor
JWT="$(grep VAMPI_AUTH_HEADER ../../Schemathesis/tokens.env | cut -d= -f2- | tr -d '\"' | sed 's/^Bearer //')" \
  python -m executor.run_nuclei --input benchmark/suite.json --export-dir ../../results/nuclei
cd ../..

# TỔNG HỢP — gộp kết quả 2 tool thành 1 báo cáo
python scripts/aggregate_results.py

# DỌN LAB khi xong
bash lab/lab.sh down
```

**Kết quả cuối** trong `results/`:
- `findings_summary.csv` — cho **người** (mở Excel).
- `findings_summary.ndjson` — cho **máy** (mỗi dòng 1 finding chuẩn hóa).

---

## 5. Chi tiết từng thành phần

### B — `scripts/gen_payloads.py`
Đọc spec → LLM sinh payload context-aware → validate bằng chính pydantic model của tool → ghi 4 file.
```bash
python scripts/gen_payloads.py                  # cả 4 file
python scripts/gen_payloads.py --only rest      # chỉ vampi + crapi
python scripts/gen_payloads.py --only graphql   # chỉ dvga
python scripts/gen_payloads.py --only nuclei    # chỉ suite nuclei
python scripts/gen_payloads.py --max-endpoints 30
```
Đổi provider LLM: `python scripts/switch_ai.py gemini|deepseek|status`.

### C — Schemathesis
Chạy gộp cả 3 target: `python Schemathesis/run_security_tests.py` (đọc `tokens.env` cho auth).
Chạy lẻ từng target: xem `Schemathesis/RUNBOOK.md`. Ghi ra `Schemathesis/results/vulnerabilities.{csv,ndjson}`.

### C — Nuclei
`python -m executor.run_nuclei --input benchmark/suite.json --export-dir <dir>` (chạy trong `Nuclei/executor/`).
Endpoint auth trong suite dùng placeholder `{{jwt}}` — truyền token thật qua biến môi trường `JWT`.

### Tổng hợp — `scripts/aggregate_results.py`
Tự dò kết quả 2 tool, chuẩn hóa, khử trùng lặp. Cờ: `--only-confirmed`, `--no-dedup`, `--input <file>`, `--out-dir <dir>`.

---

## 5b. Nhắm 1 target TÙY Ý (ngoài 3 lab mẫu)

> ⚠️ Chỉ nhắm target bạn **sở hữu hoặc có phép bằng văn bản** (pentest có hợp đồng, CTF, lab của bạn).
> Không cần Docker/`lab/` nếu target đã chạy sẵn ở một URL — bỏ qua bước A.

Cần: **spec của target** (tải từ `/openapi.json`, `/swagger.json`, `/v3/api-docs`; GraphQL thì lấy introspection JSON) và **URL target**.

```bash
# B — sinh payload cho spec của bạn (REST)
python scripts/gen_payloads.py --spec ./myapi.yaml --kind rest --target-app myapp \
       --out Schemathesis/payload_myapp.json

# C — Schemathesis bắn vào target (thêm auth nếu cần)
export FUZZ_AUTH_HEADER="Bearer <token-cua-ban>"     # bỏ nếu API không cần auth
python Schemathesis/run_schemathesis1.py \
       --targets "myapp=./myapi.yaml" --base-urls "myapp=http://TARGET:PORT" \
       --payloads Schemathesis/payload_myapp.json --rules Schemathesis/rules.json \
       --results-dir Schemathesis/results

# HOẶC dùng Nuclei
python scripts/gen_payloads.py --spec ./myapi.yaml --kind nuclei --target-app myapp \
       --base-url http://TARGET:PORT --out Nuclei/executor/benchmark/suite_myapp.json
cd Nuclei/executor
JWT="<token-cua-ban>" python -m executor.run_nuclei \
       --input benchmark/suite_myapp.json --target http://TARGET:PORT --export-dir ../../results/nuclei
cd ../..

# GraphQL: --kind graphql với file introspection
python scripts/gen_payloads.py --spec ./schema_introspection.json --kind graphql --target-app myapp \
       --out Schemathesis/payload_myapp_graphql.json

# Tổng hợp như thường
python scripts/aggregate_results.py
```

## 6. Cấu trúc thư mục

| Đường dẫn | Vai trò |
|---|---|
| `core/` | **B**: `analyzer.py` (đọc spec), `gemini_client.py`/`deepseek_client.py` (LLM), `validator.py` (guardrails) |
| `scripts/` | `gen_payloads.py` (B→C), `aggregate_results.py` (gộp), `run_pipeline.py` (cần deepcode CLI — không bắt buộc), `switch_ai.py` |
| `Schemathesis/` | **C** REST/GraphQL fuzzer + specs (`*_spec.*`), `rules.json`, `RUNBOOK.md`, `results/` |
| `Nuclei/executor/` | **C** Nuclei executor; `benchmark/suite.json` là payload nuclei |
| `lab/` | **A**: `docker-compose.yml` + `lab.sh` + `README.md` dựng 3 target |
| `dataset/` | Spec gốc + CSV inventory/ground-truth phục vụ benchmark |
| `tests/` | Unit/integration test của B (`pytest tests/ -q`, 41 test) |
| `docs/` | Nhật ký kiểm tra, USAGE, evidence |
| `Aegis Agent/` | Source deepcode CLI (chỉ cần nếu chạy `run_pipeline.py` qua deepcode — không cần cho luồng Gemini) |
| `baseline/` | Chỗ để kết quả baseline (hiện trống) |

---

## 7. Sự cố thường gặp

- **`pip install schemathesis` báo lỗi build `pydantic-core`** → đang dùng Python 3.14. Chuyển sang Python 3.11–3.13.
- **`.env` mất sau khi git clone** → đúng thiết kế (bị `.gitignore`). Tạo lại `.env` với `GEMINI_API_KEY`.
- **`lab.sh` tải crAPI báo 404** → mở `lab/lab.sh`, đổi `main` → `develop` trong `CRAPI_URL`.
- **Docker báo "daemon not running"** → bật Docker (Linux: `sudo systemctl start docker`).
- **Nuclei trả 401 ở endpoint auth** → chưa truyền `JWT=<token>`; lấy token từ `Schemathesis/tokens.env`.
- **`tokens.env` MISSING** → chạy `run_auth.py` + `run_dvga.py` khi target đã chạy.

---

## 8. Kiểm thử hệ thống

```bash
pytest tests/ -q     
```

Xem thêm: `lab/README.md` (chi tiết lab), `Schemathesis/RUNBOOK.md` (chạy lẻ schemathesis),
`docs/USAGE.md` (luồng qua deepcode CLI — tuỳ chọn).
