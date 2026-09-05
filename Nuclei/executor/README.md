# Nuclei Executor

Nuclei Executor is the execution component of the **LLM-Assisted API Fuzzing** system.

It converts structured API security test cases into temporary [Nuclei](https://github.com/projectdiscovery/nuclei) templates, executes those templates against the target API, collects the runtime results, and normalizes the findings into a machine-readable result model.

The component is designed to be deterministic, reproducible, and usable both as part of the main fuzzing workflow and as a standalone execution utility.

---

## 1. Responsibilities

Nuclei Executor is responsible for four main operations:

1. **Validate test specifications**
   - Validate the input JSON using the Pydantic models defined in `schemas.py`.
   - Validate the target URL.
   - Validate individual test cases, HTTP methods, severity values, and matchers.

2. **Build Nuclei templates**
   - Convert each API security test case into a temporary Nuclei YAML template.
   - Resolve path parameters and query parameters.
   - Configure HTTP method, headers, body, payload, and matchers.
   - Preserve the test-case identifier so runtime findings can be mapped back to the original test case.

3. **Execute Nuclei**
   - Invoke the Nuclei binary through `nuclei_runner.py`.
   - Execute generated templates against the configured target.
   - Capture structured Nuclei output.

4. **Normalize results**
   - Convert raw Nuclei output into the project's normalized finding model.
   - Produce execution statistics.
   - Export machine-readable and human-readable results when requested.

---

## 2. Execution Flow

The executor follows this flow:

```text
Structured Test Specification
            │
            ▼
        schemas.py
            │
            │ validation
            ▼
     template_builder.py
            │
            │ generate temporary YAML
            ▼
      Nuclei Template(s)
            │
            ▼
     nuclei_runner.py
            │
            │ subprocess execution
            ▼
          Nuclei
            │
            │ JSON / JSONL results
            ▼
       run_nuclei.py
            │
            │ normalization
            ▼
      ExecutorResult
            │
            ├── summary
            └── findings
```

The executor does not own API discovery, LLM reasoning, payload generation strategy, or application-level vulnerability triage. Its responsibility is to provide a reliable execution boundary between structured security test specifications and Nuclei runtime results.

---

## 3. Directory Structure

```text
Nuclei/
└── executor/
    ├── __init__.py
    ├── README.md
    ├── RUNBOOK.md
    ├── requirements.txt
    ├── run_nuclei.py
    ├── schemas.py
    ├── template_builder.py
    ├── nuclei_runner.py
    │
    ├── tools/
    │   └── suite_from_openapi.py
    │
    └── benchmark/
        └── ...
```

### Core files

| File | Responsibility |
|---|---|
| `run_nuclei.py` | CLI entrypoint, orchestration, result normalization, and exports |
| `schemas.py` | Input/output data models and validation |
| `template_builder.py` | Converts test cases into Nuclei templates |
| `nuclei_runner.py` | Nuclei subprocess execution and runtime handling |
| `tools/suite_from_openapi.py` | Utility for creating a test specification from an OpenAPI document |
| `requirements.txt` | Python dependencies |

---

## 4. Requirements

### Python

Use a supported Python 3 environment.

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

### Nuclei

Nuclei must be installed separately.

Verify the installation:

```bash
nuclei -version
```

If the executable is not available through `PATH`, configure:

```bash
export NUCLEI_BIN=/path/to/nuclei
```

On Windows, running the executor through WSL/Linux is recommended when the local Nuclei installation is restricted by the operating system or endpoint security controls.

---

## 5. Input Contract

The executor accepts a JSON document containing:

- `target`
- `test_cases`
- optional `variables`

A simplified example:

```json
{
  "target": "http://127.0.0.1:8000",
  "test_cases": [
    {
      "id": "api-001",
      "endpoint": "/api/users/{id}",
      "method": "GET",
      "vuln_type": "idor",
      "path_params": {
        "id": 1
      },
      "query_params": {},
      "body": null,
      "payload": null,
      "headers": {},
      "matchers": {
        "status": [200],
        "words": [],
        "regex": [],
        "dsl": [],
        "condition": "or"
      },
      "severity": "high"
    }
  ],
  "variables": {}
}
```

The authoritative schema is implemented in `schemas.py`.

### Test case fields

| Field | Description |
|---|---|
| `id` | Unique identifier for the test case |
| `endpoint` | API endpoint path; must start with `/` |
| `method` | HTTP method |
| `vuln_type` | Vulnerability category being tested |
| `headers` | Optional HTTP headers |
| `path_params` | Values used to resolve endpoint path parameters |
| `query_params` | Query parameters |
| `body` | Optional request body |
| `payload` | Optional payload value |
| `matchers` | Conditions used to determine a match |
| `severity` | Expected severity classification |

Supported HTTP methods currently include:

```text
GET
POST
PUT
PATCH
DELETE
HEAD
OPTIONS
```

Supported severity values are:

```text
info
low
medium
high
critical
```

---

## 6. Output Contract

The normalized execution result contains:

```json
{
  "target": "http://127.0.0.1:8000",
  "summary": {
    "total": 1,
    "matched": 1,
    "errors": 0,
    "duration_sec": 0.84
  },
  "findings": [
    {
      "id": "api-001",
      "endpoint": "/api/users/{id}",
      "vuln_type": "idor",
      "matched": true,
      "severity": "high",
      "matched_at": "http://127.0.0.1:8000/api/users/1",
      "response_status": 200,
      "evidence": "...",
      "raw": {}
    }
  ]
}
```

The output model is defined by `ExecutorResult` in `schemas.py`.

### Summary

The `summary` object contains:

- `total`
- `matched`
- `errors`
- `duration_sec`

### Finding

Each finding can contain:

- test-case ID
- endpoint
- vulnerability type
- match state
- severity
- matched URL
- response status
- evidence
- raw runtime information

Raw runtime information is preserved where available to support debugging and reproducibility.

---

## 7. Running the Executor

### Basic execution

```bash
python -m executor.run_nuclei --input suite.json
```

The input file must follow the schema described above.

### Override the target

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --target http://127.0.0.1:8000
```

### Write normalized JSON output

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --target http://127.0.0.1:8000 \
  --output result.json \
  --json
```

### Export result files

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --export-dir results
```

The export directory can contain machine-readable and human-readable result artifacts depending on the execution options implemented by the current CLI.

---

## 8. Generating Test Specifications from OpenAPI

The repository also provides:

```text
tools/suite_from_openapi.py
```

This utility can be used to construct a structured test specification from an OpenAPI document.

It is a utility for preparing executor input. It is not a replacement for another pipeline component.

The resulting specification must still satisfy the executor schema before execution.

---

## 9. Template Generation

`template_builder.py` converts a validated `Case` into a Nuclei HTTP template.

The builder handles:

- endpoint construction
- path parameter substitution
- query parameter encoding
- HTTP methods
- request headers
- request body
- payloads
- status matchers
- word matchers
- regex matchers
- DSL matchers

Template IDs are derived from the test-case identity and vulnerability type so findings can be mapped back to their originating test case.

Generated templates are temporary execution artifacts and should not be treated as the canonical test specification.

---

## 10. Runtime Execution

`nuclei_runner.py` provides the runtime boundary around the Nuclei executable.

Its responsibilities include:

- locating the Nuclei binary
- invoking Nuclei
- passing generated templates and runtime options
- capturing stdout/stderr
- handling process failures
- returning structured execution information to the executor

The executor therefore keeps Nuclei-specific process handling separate from schema validation and template construction.

---

## 11. Result Interpretation

A `matched` finding means that the configured Nuclei matcher conditions were satisfied during execution.

It does **not automatically mean that the application vulnerability has been conclusively proven**.

For example:

```text
matched = true
```

means:

```text
The runtime response satisfied the configured detection conditions.
```

The final security assessment should consider:

- request context
- authentication state
- authorization context
- expected application behavior
- matcher quality
- response evidence
- reproducibility
- potential false positives

The executor is therefore an execution and evidence-collection component rather than a complete vulnerability adjudication system.

---

## 12. Reproducibility

For reproducible security evaluation, preserve:

1. input test specification
2. target URL
3. executor version/commit
4. Nuclei version
5. generated template when debugging
6. normalized output
7. raw runtime output when available
8. execution timestamp
9. relevant authentication/configuration state

A finding should ideally be reproducible using the same input specification and target configuration.

---

## 13. Failure Modes

Common failures include:

### Nuclei not installed

```text
nuclei: command not found
```

Fix:

```bash
nuclei -version
```

or configure:

```bash
export NUCLEI_BIN=/path/to/nuclei
```

### Invalid input schema

The executor rejects malformed test specifications through the Pydantic models in `schemas.py`.

Check:

```text
target
test_cases
endpoint
method
vuln_type
matchers
severity
```

### Invalid endpoint

Endpoints must start with `/`.

Valid:

```text
/api/users
```

Invalid:

```text
api/users
```

### Empty matcher configuration

A test case without meaningful matcher conditions can produce a template that does not provide useful detection logic.

Review the `matchers` configuration before execution.

### Target unavailable

Verify:

```bash
curl -i http://127.0.0.1:8000
```

and confirm that the target is reachable from the environment where Nuclei is executed.

### Authentication failure

If the target requires authentication, verify that the required headers or authentication context are present in the generated test specification and that the target accepts them.

---

## 14. Security Considerations

Nuclei Executor performs active security testing against the configured target.

Only execute it against:

- systems you own,
- systems you are authorized to test,
- intentionally vulnerable environments,
- approved security-testing targets.

Some test cases may generate requests that modify application state or trigger application-side behavior.

Use a dedicated test environment whenever possible.

---

## 15. Relationship to the Main System

Nuclei Executor is one execution capability within the broader **LLM-Assisted API Fuzzing** project.

The broader system can provide structured security test cases and consume normalized findings, while this component focuses specifically on:

```text
test specification
        ↓
template construction
        ↓
Nuclei execution
        ↓
result normalization
```

This separation keeps the executor reusable and independently testable.

---

## 16. Development Principles

Changes to the executor should preserve:

- stable input/output schemas
- deterministic template generation
- reproducible execution
- clear mapping between test cases and findings
- separation between template construction and process execution
- machine-readable result formats
- useful runtime diagnostics

When modifying the schema, update the corresponding documentation and test fixtures together.

---

## 17. Quick Reference

```bash
# Install Python dependencies
pip install -r requirements.txt

# Verify Nuclei
nuclei -version

# Run executor
python -m executor.run_nuclei --input suite.json

# Override target
python -m executor.run_nuclei \
  --input suite.json \
  --target http://127.0.0.1:8000

# Write JSON result
python -m executor.run_nuclei \
  --input suite.json \
  --output result.json \
  --json

# Export results
python -m executor.run_nuclei \
  --input suite.json \
  --export-dir results
```

---

## 18. Source of Truth

For implementation details, treat the following files as authoritative:

```text
schemas.py
template_builder.py
nuclei_runner.py
run_nuclei.py
```

This README describes the current architecture and intended usage; implementation behavior is determined by the source code.