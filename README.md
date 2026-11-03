# LLM-Assisted API Fuzzing

LLM-assisted API fuzzing framework for generating, validating, repairing, executing, and evaluating context-aware API attack payloads from OpenAPI/Swagger specifications.

The project follows a unified architecture with interchangeable LLM providers.

Current supported providers:

- **Google Gemini** (`gemini` - default model: `gemini-3.7-flash`)
- **DeepSeek** (`deepseek` - default model: `deepseek-chat`)
- **Local / On-Premise LLMs** (`local`, `ollama`, `vllm` - OpenAI compatible, default: `qwen2.5-coder`)

The project follows the principle:

> **ONE PIPELINE, MULTIPLE LLM PROVIDERS**

Gemini, DeepSeek, and Local LLMs are provider implementations of the same LLM layer. They share the exact same OpenAPI parsing, Data Masking/Unmasking, Pydantic Guardrails, Safe Mode filtering, Concurrent Execution Engine, Enhanced Oracle analysis, and OASIS SARIF v2.1.0 reporting.

---

# 🚀 Quick Start — Web Management UI or Single-Command CLI

### Option A: Clean Web Management UI (Interactive Form & Live Console)
Launch the interactive web console (Light theme: White, Soft Slate, Indigo — no distracting SOC/SIEM dark neon):
```bash
# Start Web UI and automatically open browser
python fuzzer.py ui --open-browser
# or directly:
python web_ui.py
```
*Access in browser at:* `http://127.0.0.1:5000`

### Option B: Unified CLI Entrypoint (`fuzzer.py scan`)

```bash
# 1. Full Lifecycle Scan in Dry-Run Mode (Spec analysis -> Masking -> LLM gen -> Guardrails -> Safe mode -> SARIF)
python fuzzer.py scan dataset/vampi_openapi.json --provider gemini --dry-run

# 2. Live Fuzzing Scan against target API (Concurrent multi-threading)
python fuzzer.py scan dataset/vampi_openapi.json -u http://localhost:5002 --provider local --concurrency 10

# 3. Enterprise Real-world Target (Custom IP/Domain, Self-signed SSL, Proxy, Custom Headers, Rate Limiting)
python fuzzer.py scan https://staging-api.corp.com/v3/api-docs \
  -u https://staging-api.corp.com \
  --target-name "CoreBankingSvc" \
  --insecure \
  --header "X-Tenant-Id: corp_vn" \
  --delay 50 --max-rps 20 \
  --token "Bearer eyJhbGci..."

# 4. Auto-Discovery on Unknown Target (Automatically probe /openapi.json, /v3/api-docs...)
python fuzzer.py scan auto -u http://192.168.1.100:8000 --auto-discover --target-name "InternalMicroservice"

# 5. Schema-less / Raw Endpoints Fuzzing (When target has no Swagger/OpenAPI)
python fuzzer.py scan endpoints.txt -u http://10.0.0.15:8080 --target-name "LegacyOrdersAPI"
```

### CLI Arguments for `fuzzer.py scan`:
- `spec`: Path to OpenAPI/Swagger spec (JSON/YAML), remote URL (`https://...`), raw endpoints list (`.txt`), or `'auto'`.
- `-u, --target-url`: Target server IP or URL for live fuzzing.
- `--target-name, --app`: Custom target application name for SARIF / CSV reporting.
- `-p, --provider`: LLM provider (`gemini`, `deepseek`, `local`, `ollama`, `vllm`).
- `-m, --model`: Specific LLM model name.
- `-o, --out-dir`: Output directory for reports (default: `results`).
- `-t, --token, --auth-token`: Bearer token or credentials header value.
- `--auth-header`: Header name (default: `Authorization`).
- `--auth-prefix`: Token prefix (default: `Bearer `).
- `-H, --header`: Additional custom HTTP headers (e.g. `-H "X-API-Key: 123" -H "X-Tenant: corp"`).
- `-k, --insecure`: Skip SSL certificate verification (useful for internal IPs / self-signed certs).
- `--proxy`: HTTP/HTTPS upstream proxy (e.g. `http://127.0.0.1:8080` for Burp Suite / OWASP ZAP).
- `--delay`: Delay between requests in milliseconds (avoids overloading staging environments).
- `--max-rps`: Rate limiting - maximum requests per second.
- `--scope`: Add allowed hostnames (Scope Guard to prevent fuzzing out-of-scope third parties).
- `--auto-discover`: Automatically probe for OpenAPI specs on the target host.
- `--raw-endpoints`: Path to raw endpoints list (`.txt` or JSON) when OpenAPI spec is unavailable.
- `-c, --concurrency`: Number of concurrent worker threads (default: `5`).
- `--timeout`: HTTP timeout per request in seconds (default: `8.0`).
- `--no-safe-mode`: Disable safe mode (allows testing `DELETE` and destructive endpoints).
- `--no-mask-data`: Disable PII & internal IP/domain masking.
- `--fail-on`: Security gate threshold (`critical`, `high`, `medium`, `low`, `info`).

---

---

# 1. Architecture

```text
OpenAPI / Swagger
        │
        ▼
core/analyzer.py
        │
        ▼
Structured API Context
        │
        ▼
core/prompt_builder.py
        │
        ▼
LLM Provider Abstraction
        │
        ├───────────────┬───────────────┐
        ▼               ▼               ▼
     Gemini          DeepSeek        Future
     Provider        Provider        Provider
        │               │
        └───────────────┴───────────────┘
                        │
                        ▼
                 Raw LLM Output
                        │
                        ▼
                core/validator.py
                        │
                 ┌──────┴──────┐
                 │             │
               Valid         Invalid
                 │             │
                 │             ▼
                 │       Same LLM Provider
                 │             │
                 │           Repair
                 │             │
                 └──────┬──────┘
                        ▼
                Validated Payload
                        │
                        ▼
              Schemathesis / Nuclei
                        │
                        ▼
                    Findings
                        │
                        ▼
                   Evaluation
                        │
                        ▼
                    Manifest
```

---

# 2. Core Design

The system is organized around a single pipeline.

```text
                  Unified Pipeline
                         │
             ┌───────────┴───────────┐
             │                       │
          Gemini                  DeepSeek
        Provider                  Provider
             │                       │
             └───────────┬───────────┘
                         │
                         ▼
                Common Fuzzing Flow
```

The provider only controls the LLM interaction.

The following stages are shared:

- OpenAPI/Swagger analysis
- API context construction
- Prompt construction
- Payload validation
- Payload repair
- Fuzzing
- Finding/oracle processing
- Evaluation
- Telemetry
- Manifest generation

This allows different LLM providers to be evaluated under the same pipeline.

---

# 3. Project Structure

Important runtime components:

```text
LLM-Assisted-API-Fuzzing/
│
├── core/
│   ├── analyzer.py
│   ├── providers.py
│   ├── gemini_client.py
│   ├── deepseek_client.py
│   ├── prompt_builder.py
│   ├── validator.py
│   ├── telemetry.py
│   ├── manifest.py
│   └── evaluation.py
│
├── scripts/
│   ├── run_pipeline.py
│   └── ...
│
├── tests/
│   ├── test_run_pipeline.py
│   └── ...
│
├── Schemathesis/
├── Nuclei/
├── LLM/
└── README.md
```

### Canonical runtime entry point

```text
scripts/run_pipeline.py
```

### Provider abstraction

```text
core/providers.py
```

### API analysis

```text
core/analyzer.py
```

### Shared prompt construction

```text
core/prompt_builder.py
```

### Payload validation

```text
core/validator.py
```

### Telemetry

```text
core/telemetry.py
```

---

# 4. LLM Provider Abstraction

The provider abstraction is implemented in:

```text
core/providers.py
```

It provides a common interface for LLM operations such as:

```text
generate()
repair()
metadata
```

The current provider registry contains:

```text
PROVIDERS
├── gemini
└── deepseek
```

Provider instances are resolved through:

```text
get_provider()
```

The main pipeline therefore does not need to implement a separate fuzzing workflow for every LLM.

---

# 5. Gemini Provider

Gemini is implemented as one provider of the unified LLM layer.

Provider-specific client:

```text
core/gemini_client.py
```

Runtime selection:

```bash
python scripts/run_pipeline.py --provider gemini
```

A model can also be selected explicitly:

```bash
python scripts/run_pipeline.py \
    --provider gemini \
    --model gemini-3.7-flash
```

The exact model available depends on the configured Gemini API and the provider implementation.

---

# 6. DeepSeek Provider

DeepSeek is implemented as another provider of the same unified LLM layer.

Provider-specific client:

```text
core/deepseek_client.py
```

Runtime selection:

```bash
python scripts/run_pipeline.py --provider deepseek
```

A model can also be selected explicitly:

```bash
python scripts/run_pipeline.py \
    --provider deepseek \
    --model deepseek-chat
```

Gemini and DeepSeek use the same downstream pipeline.

---

# 7. Runtime Provider Selection

Provider selection is performed at runtime.

The provider must be explicitly specified:

```bash
python scripts/run_pipeline.py --provider gemini
```

or:

```bash
python scripts/run_pipeline.py --provider deepseek
```

Supported providers are currently:

```text
gemini
deepseek
```

Unsupported providers are rejected explicitly.

There is no silent provider fallback.

The canonical provider resolution flow is:

```text
CLI
 │
 ▼
_resolve_provider()
 │
 ▼
get_provider()
 │
 ▼
Provider Instance
 │
 ▼
Unified Pipeline
```

---

# 8. Runtime Model Selection

The selected model is passed to the provider at runtime.

Example:

```bash
python scripts/run_pipeline.py \
    --provider gemini \
    --model gemini-3.7-flash
```

Example:

```bash
python scripts/run_pipeline.py \
    --provider deepseek \
    --model deepseek-chat
```

The model used by the provider is propagated into pipeline metadata and the manifest when available.

---

# 9. API Key Configuration

API keys are configured through environment variables.

## Gemini

```text
GEMINI_API_KEY
```

Linux/Kali/Ubuntu:

```bash
export GEMINI_API_KEY="YOUR_GEMINI_KEY"
```

Windows PowerShell:

```powershell
$env:GEMINI_API_KEY="YOUR_GEMINI_KEY"
```

## DeepSeek

```text
DEEPSEEK_API_KEY
```

Linux/Kali/Ubuntu:

```bash
export DEEPSEEK_API_KEY="YOUR_DEEPSEEK_KEY"
```

Windows PowerShell:

```powershell
$env:DEEPSEEK_API_KEY="YOUR_DEEPSEEK_KEY"
```

API keys must not be hard-coded into the repository.

If the required key is missing, the selected provider should return an explicit configuration error.

The system does not silently switch to another provider.

---

# 10. Main Pipeline

The canonical pipeline is:

```text
scripts/run_pipeline.py
        │
        ▼
Provider Resolution
        │
        ▼
OpenAPI / Swagger Analysis
        │
        ▼
Structured API Context
        │
        ▼
Shared Prompt Builder
        │
        ▼
LLM Generation
        │
        ▼
Payload Validation
        │
        ├── Valid ───────────────┐
        │                        │
        └── Invalid              │
                │                │
                ▼                │
          Same Provider          │
                │                │
              Repair             │
                │                │
                ▼                │
             Validate            │
                │                │
                └────────────────┘
                         │
                         ▼
                 Validated Payload
                         │
                         ▼
               Schemathesis / Nuclei
                         │
                         ▼
                     Findings
                         │
                         ▼
                    Evaluation
                         │
                         ▼
                     Manifest
```

---

# 11. API Analysis

API analysis is handled by:

```text
core/analyzer.py
```

The analyzer processes the OpenAPI/Swagger specification and creates structured API context for the LLM.

The analyzer is provider-independent.

Therefore, the same API specification can be processed as:

```text
OpenAPI
   ↓
Analyzer
   ↓
API Context
   ↓
Gemini
```

or:

```text
OpenAPI
   ↓
Analyzer
   ↓
API Context
   ↓
DeepSeek
```

This is important for controlled provider comparison.

---

# 12. Shared Prompt Builder

Prompt construction is implemented in:

```text
core/prompt_builder.py
```

The prompt builder is shared by all providers.

The pipeline follows:

```text
API Context
     ↓
Prompt Builder
     ↓
Selected LLM Provider
     ↓
Raw LLM Response
```

There is no separate Gemini prompt pipeline or DeepSeek prompt pipeline in the canonical architecture.

---

# 13. Payload Validation

Payload validation is implemented in:

```text
core/validator.py
```

Validation is provider-independent.

The flow is:

```text
LLM Output
    │
    ▼
Validator
    │
    ├── Valid
    │     ↓
    │   Continue
    │
    └── Invalid
          ↓
        Repair
          ↓
      Same Provider
          ↓
       Validator
```

The repair operation uses the same provider that generated the original payload.

Example:

```text
Gemini
  ↓
Generate
  ↓
Invalid
  ↓
Gemini
  ↓
Repair
```

and:

```text
DeepSeek
  ↓
Generate
  ↓
Invalid
  ↓
DeepSeek
  ↓
Repair
```

The repair stage does not automatically switch providers.

---

# 14. Telemetry

LLM telemetry is handled by:

```text
core/telemetry.py
```

The provider response can contain metadata such as:

```text
reply
model
usage
latency
```

The pipeline preserves this information.

Telemetry can contain:

```text
prompt tokens
completion tokens
total tokens
```

Generation and repair usage are accumulated when usage information is provided by the provider.

Example:

```text
Generation:
prompt = 10
completion = 4
total = 14

Repair:
prompt = 3
completion = 2
total = 5

Accumulated:
prompt = 13
completion = 6
total = 19
```

---

# 15. Token Usage Handling

Token usage is recorded only when the provider exposes usable token metadata.

The project does not estimate tokens from runtime.

For example, if the provider does not expose token usage:

```text
usage_available = false
prompt_tokens = null
completion_tokens = null
total_tokens = null
```

The system does not invent token values.

This distinction is important for research evaluation because runtime and token consumption are different measurements.

---

# 16. Manifest

The pipeline records run metadata in the manifest.

Relevant information can include:

```text
provider
model
runtime
repair count
token usage
```

The manifest allows experimental runs to be compared and analyzed.

Conceptually:

```text
Pipeline Run
     │
     ├── Provider
     ├── Model
     ├── Runtime
     ├── Repairs
     └── Token Usage
              │
              ▼
           Manifest
```

---

# 17. DeepCode

DeepCode is not treated as an LLM provider in the current architecture.

The previous DeepCode provider/fallback execution path has been removed from the canonical pipeline.

Current LLM providers:

```text
Gemini
DeepSeek
```

An unsupported provider does not cause the system to silently execute DeepCode or another provider.

DeepSeek and DeepCode are separate concepts:

```text
DeepSeek
    = LLM provider

DeepCode
    = tooling/integration component
```

---

# 18. Schemathesis and Nuclei

Schemathesis and Nuclei are downstream components of the unified fuzzing flow.

They are not tied to a specific LLM provider.

The architecture is:

```text
Gemini ────────┐
               │
               ▼
          Validated Payload
               ▲
               │
DeepSeek ──────┘
               │
               ▼
      Schemathesis / Nuclei
               │
               ▼
           Findings
```

The LLM layer focuses on generation and repair.

The downstream fuzzing and evaluation stages remain shared.

---

# 19. Testing

Automated tests are located under:

```text
tests/
```

Run the test suite with:

```bash
python -m pytest tests/ -q
```

The tests cover the main provider and pipeline contracts, including:

- provider resolution
- supported provider handling
- unsupported provider handling
- runtime provider selection
- model propagation
- generation
- repair
- same-provider repair
- telemetry
- token usage propagation
- manifest metadata
- missing token usage handling
- prevention of fake token values

The test suite is intended to protect the unified architecture against regressions.

---

# 20. Running the Project

## 20.1 Verify Python

```bash
python --version
```

## 20.2 Run automated tests

```bash
python -m pytest tests/ -q
```

## 20.3 Configure Gemini

```bash
export GEMINI_API_KEY="YOUR_GEMINI_KEY"
```

Then:

```bash
python scripts/run_pipeline.py --provider gemini
```

## 20.4 Configure DeepSeek

```bash
export DEEPSEEK_API_KEY="YOUR_DEEPSEEK_KEY"
```

Then:

```bash
python scripts/run_pipeline.py --provider deepseek
```

---

# 21. Provider Comparison

The architecture allows the same experiment to be executed with different providers.

Example:

```text
                 Same OpenAPI
                      │
             ┌────────┴────────┐
             │                 │
             ▼                 ▼
          Gemini            DeepSeek
             │                 │
             ▼                 ▼
          Generate           Generate
             │                 │
             ▼                 ▼
         Validate           Validate
             │                 │
             ▼                 ▼
           Repair             Repair
             │                 │
             └────────┬────────┘
                      ▼
              Same downstream
                 pipeline
```

For a fair comparison, keep the following constant:

- OpenAPI/Swagger specification
- API target
- payload budget
- validation rules
- downstream fuzzing configuration
- evaluation procedure

Change only the LLM provider/model being evaluated.

---

# 22. Research Evaluation

The architecture supports evaluation of questions such as:

> How does the choice of LLM provider affect automated API attack-payload generation and fuzzing effectiveness?

Potential evaluation metrics include:

```text
Payload validity
Payload diversity
Repair rate
Successful execution rate
Detected vulnerabilities
False positives
Token consumption
Execution time
```

The provider abstraction allows additional LLM providers to be added without creating another fuzzing pipeline.

A future provider can follow:

```text
Future Provider
      ↓
Implement common provider interface
      ↓
Register provider
      ↓
Use existing pipeline
```

---

# 23. Development Principles

The current implementation follows these principles:

### One pipeline

There is one canonical API fuzzing pipeline.

Do not create separate:

```text
Gemini Pipeline
DeepSeek Pipeline
```

Instead:

```text
Unified Pipeline
       ↓
Selected Provider
```

### Provider abstraction

Provider-specific API interaction belongs in the provider layer.

The main pipeline should remain provider-independent.

### Same-provider repair

A payload generated by Gemini is repaired by Gemini.

A payload generated by DeepSeek is repaired by DeepSeek.

### No silent fallback

Unsupported providers must fail explicitly.

### Honest telemetry

Unavailable token usage must remain unavailable.

Do not infer token usage from runtime.

### Shared evaluation

Provider comparison should use the same downstream fuzzing and evaluation pipeline.

---

# 24. Current Project State

The current codebase contains:

```text
Unified LLM Provider Layer
        ↓
Gemini + DeepSeek
        ↓
Shared API Analysis
        ↓
Shared Prompt Construction
        ↓
Shared Validation
        ↓
Same-Provider Repair
        ↓
Shared Fuzzing
        ↓
Shared Evaluation
        ↓
Telemetry + Manifest
```

The main architecture is designed so that adding or comparing LLM providers does not require duplicating the API fuzzing pipeline.

The canonical runtime entry point remains:

```text
scripts/run_pipeline.py
```

The canonical provider abstraction remains:

```text
core/providers.py
```
