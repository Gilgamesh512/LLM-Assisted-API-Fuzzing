# AGENTS.md — LLM-Assisted API Fuzzing

Dự án độc lập: **Hệ thống tự động phân tích đặc tả API, sinh payload kiểm thử bảo mật context-aware bằng LLM, thực thi fuzzing có phản hồi runtime và xuất báo cáo chuẩn OASIS SARIF**.

## Kiến trúc Hệ thống hợp nhất

Toàn bộ hệ thống hoạt động như một thể thống nhất thông qua điểm nhập duy nhất `fuzzer.py` hoặc các module độc lập:

1. **Module Phân tích Đặc tả & Hứng Lưu lượng (`core/analyzer.py`, `core/har_parser.py`)**:
   - Parse OpenAPI/Swagger (JSON/YAML), hỗ trợ resolve `$ref` cục bộ & file tương đối.
   - Làm phẳng cấu trúc JSON Body lồng sâu (nested objects & array of objects) và `allOf/anyOf/oneOf`.
   - **Traffic-Driven HAR Ingestion (`core/har_parser.py`)**: Nạp file `.har` từ Chrome DevTools/Burp Suite, xây dựng kho hạt giống sống (`SeedCorpus`) gồm ID thật, CCCD, Token, Header `X-*`, DTO request body hợp lệ để vượt qua hàng rào validation của server.
   - Hỗ trợ chạy trực tiếp từ file `.har` mà không cần OpenAPI spec (`fuzzer.py scan session.har`).
2. **Module Trừu tượng hóa LLM Provider (`core/providers.py`)**:
   - Hỗ trợ đa dạng provider: Google Gemini, DeepSeek, và Local/On-premise LLM (Ollama, vLLM) tương thích chuẩn OpenAI Chat Completions.
   - Không bị vendor lock-in; hỗ trợ cờ Data Masking (`core/sanitizer.py`) bảo vệ quyền riêng tư dữ liệu.
3. **Module Xác thực & Tự sửa lỗi (`core/validator.py`)**:
   - Pydantic v2 JSON Guardrails xác thực schema `AttackPayload`.
   - Vòng lặp tự sửa lỗi (Self-Repair Loop) phản hồi lỗi trực tiếp cho LLM khi payload sai cú pháp.
   - Cung cấp cầu nối chuyển đổi tương thích với các fuzzing engines downstream (`convert_attack_payload_to_fuzz`).
4. **Chế độ An toàn, Toàn vẹn Dữ liệu & Kiểm soát Phá hủy (`core/safety.py`)**:
   - Chế độ Safe Mode chặn các HTTP methods nguy hiểm (`DELETE`, `PURGE`) và các endpoint phá hủy CSDL trên môi trường Staging.
   - **Doanh nghiệp & Audit Traceability**: Đính kèm header `X-Fuzzer-Audit: true` và `X-Fuzzer-Run-Id: <id>` trên mọi request giúp SOC/SIEM/DevOps phân tách lưu lượng kiểm thử.
   - **Tự động xuất `cleanup_manifest.json`**: Ghi vết toàn bộ tài nguyên được tạo hoặc biến đổi (POST/PUT/PATCH) kèm lệnh rollback chính xác cho DBA và DevOps hoàn tác sau kiểm thử.
5. **Engine Thực thi Fuzzing & Tương tác Runtime**:
   - `Schemathesis/` và `Nuclei/`: Tự động nạp payload và thực thi kiểm thử.
   - `core/curl_builder.py`: Tự động sinh lệnh `curl` hoàn chỉnh (1-Click Reproduce) cho mọi phát hiện, giúp lập trình viên copy-paste tái hiện lỗi ngay lập tức.
   - `core/stateful_chain.py`: Hỗ trợ fuzzing chuỗi trạng thái (Stateful Context Chaining) trích xuất dữ liệu động giữa các bước để kiểm tra BOLA/IDOR.
   - `core/tampering.py`: Kiểm thử logic không cần payload độc (Mass Assignment / Parameter Tampering & HTTP Verb Tampering/Tunneling).
   - **Deep State Loopback Verification**: Sau các request thay đổi trạng thái (POST/PUT/PATCH), tự động thực hiện request `GET` đối ứng để kiểm tra CSDL ngầm thực sự có bị biến đổi hay không, triệt tiêu báo động giả (Echo-only DTO) và phát hiện ghi đè âm thầm (Silent Persistence).
   - `core/auth_manager.py`: Tự động quản lý và refresh auth token khi gặp mã HTTP 401.
6. **Module Phân tích Phản hồi (Enhanced Oracle & Feedback Loop)**:
   - `core/oracle.py`: Phán đoán đa tầng (Regex, Time-based Blind SQLi/ReDoS, OAST callbacks, BOLA differential).
   - `core/feedback_loop.py`: Tạo prompt phản hồi cho LLM cải thiện thế hệ payload tiếp theo.
   - `core/prompt_builder.py`: Nhận diện nghiệp vụ API (Fintech/Banking, E-Commerce, IAM) định hướng LLM tấn công trúng các rủi ro logic đặc thù.
7. **Module Báo cáo & Security Gate (`core/sarif.py`, `core/baseline.py`, `core/compliance.py`, `core/html_report.py`)**:
   - **Executive OWASP API Top 10 (2023) Compliance Dashboard**: Đánh giá chỉ số tuân thủ (%) và phân loại CWE chi tiết cho CISO/Tech Lead.
   - Xuất báo cáo chuẩn công nghiệp OASIS SARIF v2.1.0 (tích hợp GitHub Advanced Security, GitLab Security Dashboard, DefectDojo).
   - Thiết lập ngưỡng chặn lỗi (Security Gate) cho pipeline CI/CD.

## Mục tiêu benchmark

Target kiểm thử chuẩn mực cục bộ: **OWASP crAPI, DVGA, VAmPI** (chạy bằng Docker compose trong `lab/`).

## Quy ước phát triển

- Python 3.11+, type hint đầy đủ, không dùng biến toàn cục ẩn.
- Không tự ý "khẳng định" một endpoint có lỗ hổng nếu chưa có bằng chứng runtime xác nhận từ Oracle/Fuzzer.
- Không hardcode API key vào git. Cung cấp qua biến môi trường (`GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `LOCAL_LLM_URL`).

## Kiểm thử tự động

```bash
python -m pytest tests/ -v
```

## Vận hành nhanh (Web UI hoặc CLI)

```bash
# Cách 1: Khởi động Web UI điều khiển trực quan (Theme Trắng - Xanh - Tím nhạt thanh lịch)
python fuzzer.py ui --open-browser
# hoặc:
python web_ui.py

# Cách 2: Quét trực tiếp qua CLI
# Quét toàn bộ vòng đời (Parse -> Mask -> Sinh -> Validate -> Safe Mode -> Báo cáo SARIF + HTML)
python fuzzer.py scan dataset/vampi_openapi.json --provider gemini --dry-run

# Chạy Fuzzing trực tiếp vào máy chủ API (hỗ trợ auth token & đa luồng)
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --provider local --token "Bearer test-jwt-token" --concurrency 10

# Quét Target thực tế Doanh nghiệp (URL/IP nội bộ, SSL tự ký, Proxy Burp Suite, Custom Headers, Rate Limiting)
python fuzzer.py scan https://api.corp.local/v3/api-docs -u https://api.corp.local --target-name "CoreBankingSvc" --insecure -H "X-Tenant: corp_vn" --delay 50 --max-rps 20

# Tự động dò tìm OpenAPI spec (Auto-Discovery) trên bất kỳ IP/URL nào
python fuzzer.py scan auto -u http://192.168.1.100:8000 --auto-discover --target-name "InternalMicroservice"

# Vòng lặp phản hồi thích ứng đa thế hệ (Adaptive Feedback Loop Fuzzing)
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --generations 3

# Kiểm thử chuỗi trạng thái tự động (Stateful Context Chaining BOLA/IDOR)
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --token "Bearer userA" --secondary-token "Bearer userB" --stateful

# Kiểm thử Logic không cần payload độc (BOLA + Mass Assignment + Verb Tampering WAF Bypass)
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --token "Bearer test-jwt-token" --logic-scan

# Hoặc bật riêng rẽ từng module Parameter Tampering hoặc Verb Tampering
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --mass-assignment --verb-tampering

# Nạp lưu lượng thực tế (Live Traffic HAR Ingestion) làm hạt giống vượt DTO validation
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --har session.har --logic-scan

# Quét trực tiếp từ file HAR mà không cần file OpenAPI spec
python fuzzer.py scan session.har -u http://localhost:5002 --concurrency 10

# Xử lý đặc tả lớn (Chunking / Batching) & So sánh Baseline Drift
python fuzzer.py scan large_spec.json -u http://localhost:8000 --chunk-size 15 --baseline results/previous_findings.ndjson
```
