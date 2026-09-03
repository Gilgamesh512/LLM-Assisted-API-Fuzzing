# LLM-API-Fuzzer

Pipeline nghiên cứu kiểm thử bảo mật API bằng fuzzing có LLM hỗ trợ. Hệ thống
đọc OpenAPI/Swagger hoặc GraphQL introspection, sinh test case context-aware,
validate output, chạy fuzzing trên các ứng dụng lab cố ý có lỗ hổng và tổng hợp
kết quả.

Phạm vi benchmark hiện tại gồm **VAmPI**, **crAPI** và **DVGA** chạy cục bộ.
Chỉ sử dụng pipeline với hệ thống bạn sở hữu hoặc được phép kiểm thử.

## Pipeline

```text
Target lab (Docker)
    |
    +--> VAmPI REST :5002
    +--> crAPI REST :8888
    +--> DVGA GraphQL :5013
             |
             v
Authentication + schema discovery
    |
    +--> Schemathesis/run_auth.py  -> tokens.env
    +--> Schemathesis/run_dvga.py  -> DVGA token + dvga_schema.json
             |
             v
Payload generation
    |
    +--> scripts/gen_payloads.py
    |       +--> payload_rest.json
    |       +--> payload_crapi.json
    |       +--> payload_graphql.json
    |       +--> Nuclei/executor/benchmark/suite.json
    |
    +--> scripts/run_pipeline.py
            +--> OpenAPI analyzer
            +--> api-payload-generator skill
            +--> Pydantic validator + repair loop
             |
             v
Security testing
    |
    +--> Schemathesis REST + GraphQL
    +--> Nuclei API executor
             |
             v
Results
    +--> scripts/aggregate_results.py
            +--> results/findings_summary.csv
            +--> results/findings_summary.ndjson
```

## Targets

| Target | Protocol | Base URL | Fuzzing component |
|---|---|---|---|
| VAmPI | REST | `http://localhost:5002` | Schemathesis |
| crAPI | REST | `http://localhost:8888` | Schemathesis |
| DVGA | GraphQL | `http://localhost:5013/graphql` | Schemathesis GraphQL |
| VAmPI | REST | `http://localhost:5002` | Nuclei |

Target configuration nằm trong [`config/targets.yaml`](config/targets.yaml).
Các spec benchmark được lưu trong `dataset/` và `Schemathesis/`.

## Cấu trúc thư mục

```text
LLM Assisted API Fuzzing/
├── core/
│   ├── analyzer.py          # Parse OpenAPI/Swagger
│   ├── validator.py         # Validate payload LLM bằng Pydantic
│   ├── gemini_client.py     # Gemini provider
│   ├── deepseek_client.py   # DeepSeek provider
│   └── feedback_loop.py     # Feedback từ runtime
├── scripts/
│   ├── run_pipeline.py      # B1 -> B4 trong một lệnh
│   ├── gen_payloads.py      # Sinh payload cho Schemathesis/Nuclei
│   ├── aggregate_results.py # Chuẩn hóa và gộp findings
│   └── switch_ai.py         # Chuyển provider LLM
├── Schemathesis/            # REST/GraphQL fuzzing runners
├── Nuclei/executor/         # Nuclei API executor
├── lab/                     # Docker Compose cho ba target
├── dataset/                 # Spec, inventory và benchmark data
├── baseline/                # Kết quả baseline
├── results/                 # Findings và runtime artifacts
├── tests/                   # Unit/integration tests
├── docs/                    # Usage, reports và evidence
└── Aegis Agent/             # Source DeepCode CLI, tùy chọn cho B2/B3
```

`tokens.env`, `context.json`, `dvga_schema.json` và dữ liệu trong `results/` là
artifact runtime. Không commit token hoặc response có dữ liệu nhạy cảm.

## Requirements

- Python **3.11-3.13**. Python 3.14 hiện chưa được hỗ trợ ổn định bởi một số
  dependency của Schemathesis/Pydantic.
- Docker và Docker Compose plugin để chạy target lab.
- `nuclei` binary trong `PATH` nếu chạy Nuclei.
- Node.js và DeepCode CLI nếu dùng `scripts/run_pipeline.py`.
- Gemini API key hoặc cấu hình DeepSeek. Không lưu API key trong repository.

Cài dependency Python:

```bash
python -m pip install -r requirements.txt
python -m pip install -r Schemathesis/requirements.txt
```

Trên Windows, có thể chạy các script Python bằng PowerShell như trên. `lab.sh`
là script Bash; dùng WSL/Git Bash hoặc chạy Docker Compose tương đương trong
[`lab/docker-compose.yml`](lab/docker-compose.yml) và compose file của crAPI.

## Quick start

### 1. Start target lab

Linux, WSL hoặc Git Bash:

```bash
bash lab/lab.sh up
bash lab/lab.sh status
```

Các target được expose ở port `5002`, `8888` và `5013`. Xem thêm
[`lab/README.md`](lab/README.md).

### 2. Generate payloads

Tạo `.env` ở project root nếu dùng Gemini:

```bash
echo 'GEMINI_API_KEY=<your-key>' > .env
```

Sinh và validate bốn nhóm output cho benchmark:

```bash
python scripts/gen_payloads.py
```

Có thể giới hạn nhóm hoặc target:

```bash
python scripts/gen_payloads.py --only rest
python scripts/gen_payloads.py --only graphql
python scripts/gen_payloads.py --target vampi
python scripts/gen_payloads.py --max-endpoints 30
```

### 3. Obtain authentication and schema

```bash
python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py
```

Hai lệnh này tạo/cập nhật `tokens.env`; bước DVGA còn tạo
`Schemathesis/dvga_schema.json` hoặc artifact schema theo cấu hình runner.

### 4. Run fuzzing

```bash
python Schemathesis/run_security_tests.py
```

Chạy Nuclei từ đúng thư mục executor:

```bash
cd Nuclei/executor
python -m executor.run_nuclei \
  --input benchmark/suite.json \
  --export-dir ../../results/nuclei
cd ../..
```

### 5. Aggregate results

```bash
python scripts/aggregate_results.py
```

Output chính:

```text
results/findings_summary.csv    # Dùng để đọc/phân tích bằng Excel
results/findings_summary.ndjson # Dùng cho xử lý tự động
```

## Run the LLM pipeline

Để chạy riêng Task B từ spec đến payload đã validate:

```bash
python scripts/run_pipeline.py path/to/openapi.yaml
python scripts/run_pipeline.py path/to/openapi.yaml \
  --provider gemini \
  --output payloads_validated.json
```

Pipeline thực hiện:

1. Parse spec bằng `core/analyzer.py` thành `context.json`.
2. Gọi skill built-in `api-payload-generator` qua DeepCode.
3. Validate JSON bằng `core/validator.py`.
4. Tự sửa output tối đa `MAX_REPAIR_ATTEMPTS` lần.
5. Ghi danh sách payload hợp lệ cho fuzzing engine.

Mỗi lần chạy thành công cũng ghi run manifest tại
`results/runs/<run_id>/manifest.json`. Manifest chứa `run_id`, target, provider,
model, payload count, repair telemetry (`attempts`, `initial_valid`,
`final_valid`, `successful`) và runtime theo stage: analyzer, LLM generation,
validation, repair và total. Có thể chỉ định đường dẫn riêng bằng
`--manifest path/to/run_manifest.json` hoặc model metadata bằng `--model`.

Khi pipeline gọi DeepCode qua subprocess, DeepCode hiện chỉ trả nội dung stdout
nên token usage không thể suy ra chính xác; manifest ghi `0` cho token cho đến
khi tầng provider/DeepCode expose usage metadata. Không dùng thời gian chạy để
ước lượng token.

DeepCode CLI được build từ source trong `Aegis Agent/`. Cài/build khi cần:

```bash
cd "Aegis Agent"
npm install
npm run build
cd ..
```

Xem hướng dẫn chi tiết về Task B trong [`docs/USAGE.md`](docs/USAGE.md).

## Run individual fuzzers

REST runner nhận spec, payload corpus, rules và thư mục kết quả:

```bash
python Schemathesis/run_schemathesis1.py \
  --targets "vampi=Schemathesis/vampi_spec.yaml" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads Schemathesis/payload_rest.json \
  --rules Schemathesis/rules.json \
  --results-dir Schemathesis/results
```

Chạy riêng DVGA GraphQL:

```bash
python Schemathesis/run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --payloads Schemathesis/payload_graphql.json \
  --rules Schemathesis/rules.json \
  --results-dir Schemathesis/results
```

Authentication được truyền qua `tokens.env` trong flow chuẩn hoặc qua
`FUZZ_AUTH_HEADER`/tùy chọn `--auth-header` tùy runner.

## Rules and feedback

Rules kiểm thử dùng chung được lưu tại [`Schemathesis/rules.json`](Schemathesis/rules.json).
Feedback runtime có thể được dùng để cải thiện thế hệ payload tiếp theo:

```bash
python scripts/run_feedback_loop.py
```

Các tín hiệu từ response hoặc CVE là context cho test case, không phải bằng
chứng độc lập rằng target có lỗ hổng. Finding chỉ nên được xem là confirmed khi
có evidence runtime phù hợp.

## Results and confirmation

Pipeline lưu kết quả chi tiết của Schemathesis trong `Schemathesis/results/`
và kết quả Nuclei trong `results/nuclei/`, sau đó chuẩn hóa vào `results/`.
Finding thường gồm target, endpoint, method, attack type, OWASP category,
payload, status code, response time, evidence, severity và trạng thái xác nhận.

Không coi mọi response lỗi là vulnerability confirmed:

- HTTP `5xx` là tín hiệu mạnh nhưng vẫn cần xem evidence.
- Chuỗi chung như `error`, `exception` hoặc `debug` không đủ để kết luận.
- GraphQL error không tự động là lỗ hổng.
- CVE match chỉ là thông tin ngữ cảnh, không chứng minh khai thác thành công.

## Research evaluation

Để so sánh công bằng, mỗi treatment phải dùng cùng target, endpoint set, timeout,
số lần chạy và seed. Protocol khuyến nghị:

| Treatment | Generator | Validation | Feedback |
|---|---|---:|---:|
| B0 | Schemathesis default | No | No |
| B1 | Schemathesis + handcrafted payload | No | No |
| P0 | LLM | No | No |
| P1 | LLM | Yes | No |
| P2 | LLM | Yes | Yes |

Mỗi run cần lưu model/provider, prompt version, temperature, schema hash, token
usage, repair count, runtime, payload artifact và findings artifact. Tạo một
manifest JSON, trong đó mỗi phần tử `runs` trỏ tới một file payload JSON/NDJSON
và một file findings JSON/NDJSON, rồi chạy:

```bash
python scripts/evaluate_experiment.py path/to/experiment_manifest.json \
  --output results/experiment_metrics.json
```

Evaluator xuất các metric `valid_payload_rate`, `executability_rate`,
`unique_payload_rate`, `confirmed_findings`, `detection_rate`,
`false_positive_rate`, `runtime_seconds`, `llm_cost_usd` và attribution theo
source engine/payload source. `confirmed` chỉ được tính khi finding có xác nhận;
candidate bị bác bỏ phải ghi `confirmation_status: "rejected"` để đo false positive.

## Testing

```bash
python -m pytest tests/ -v
```

## Security notes

- Chỉ chạy fuzzing với VAmPI, crAPI, DVGA hoặc target có ủy quyền rõ ràng.
- Không commit `.env`, `tokens.env`, API key hoặc output chứa dữ liệu nhạy cảm.
- Giữ token ở user-level settings khi dùng DeepCode/DeepSeek; không đưa key vào
  source code hay project config commit lên git.
- Dừng lab sau khi hoàn thành:

```bash
bash lab/lab.sh down
```

## References

- [`docs/USAGE.md`](docs/USAGE.md) - Task B và DeepCode integration.
- [`lab/README.md`](lab/README.md) - Cài đặt và vận hành target lab.
- [`Schemathesis/RUNBOOK.md`](Schemathesis/RUNBOOK.md) - Chạy Schemathesis từng target.
- [`AGENTS.md`](AGENTS.md) - Phạm vi, quy ước và ownership của workspace.
