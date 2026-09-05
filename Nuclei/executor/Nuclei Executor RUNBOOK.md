# Nuclei Executor Runbook

Operational runbook for running, validating, troubleshooting, and reproducing Nuclei-based API security execution.

---

## 1. Purpose

This runbook provides the operational procedure for executing the Nuclei Executor safely and consistently.

The executor performs the following sequence:

```text
Input Test Specification
        │
        ▼
Schema Validation
        │
        ▼
Template Generation
        │
        ▼
Nuclei Execution
        │
        ▼
Runtime Result Collection
        │
        ▼
Finding Normalization
        │
        ▼
Result Export
```

The objective is to produce reproducible security-testing results from a structured set of API test cases.

---

## 2. Preconditions

Before running the executor, verify:

- Python is installed.
- Python dependencies are installed.
- Nuclei is installed.
- Nuclei is available through `PATH` or `NUCLEI_BIN`.
- The target API is reachable.
- The test target is authorized for active security testing.
- The input test specification follows the executor schema.

---

## 3. Environment Setup

From the executor directory:

```bash
cd Nuclei/executor
```

Create or activate a virtual environment if required:

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Verify Python:

```bash
python --version
```

Verify Nuclei:

```bash
nuclei -version
```

If Nuclei is not in `PATH`:

```bash
export NUCLEI_BIN=/path/to/nuclei
```

Windows PowerShell:

```powershell
$env:NUCLEI_BIN="C:\path\to\nuclei.exe"
```

---

## 4. Verify the Target

Before active execution, verify that the target is reachable.

Example:

```bash
curl -i http://127.0.0.1:8000
```

For HTTPS:

```bash
curl -k -i https://127.0.0.1:8443
```

Confirm:

- hostname resolves correctly
- port is reachable
- API service is running
- required authentication is available
- the environment is the intended test environment

Do not proceed if the target identity is uncertain.

---

## 5. Validate the Input

The executor expects a structured JSON document.

Example:

```json
{
  "target": "http://127.0.0.1:8000",
  "test_cases": [
    {
      "id": "api-001",
      "endpoint": "/api/users/{id}",
      "method": "GET",
      "vuln_type": "idor",
      "headers": {},
      "path_params": {
        "id": 1
      },
      "query_params": {},
      "body": null,
      "payload": null,
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

Important validation rules:

```text
target       → must be HTTP(S)
test_cases   → must contain at least one test case
endpoint     → must start with /
method       → must be a supported HTTP method
id           → must not be empty
severity     → must use a supported severity value
```

The actual validation is implemented in:

```text
schemas.py
```

---

## 6. Standard Execution

Run:

```bash
python -m executor.run_nuclei --input suite.json
```

For an explicit target:

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --target http://127.0.0.1:8000
```

The target override is useful when the same test specification needs to be executed against different environments.

---

## 7. Save Normalized Results

To write a JSON result:

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --output result.json \
  --json
```

After execution:

```bash
cat result.json
```

The normalized result contains:

```text
target
summary
findings
```

The summary provides:

```text
total
matched
errors
duration_sec
```

---

## 8. Export Results

To export execution artifacts:

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --export-dir results
```

Inspect the directory:

```bash
find results -maxdepth 2 -type f -print
```

On Windows PowerShell:

```powershell
Get-ChildItem -Recurse results
```

Preserve the generated files when an execution needs to be audited or reproduced.

---

## 9. Execution Lifecycle

The executor processes each run through these stages.

### Stage 1 — Input loading

`run_nuclei.py` loads the JSON input.

### Stage 2 — Schema validation

`schemas.py` validates the input.

Invalid input should fail before active execution whenever possible.

### Stage 3 — Template generation

`template_builder.py` converts each test case into a Nuclei HTTP template.

The builder resolves:

```text
endpoint
path parameters
query parameters
headers
body
payload
matchers
```

### Stage 4 — Nuclei execution

`nuclei_runner.py` starts the Nuclei process and captures runtime output.

### Stage 5 — Result parsing

The executor reads Nuclei runtime results.

### Stage 6 — Finding normalization

Raw findings are converted into the project's normalized `Finding` model.

### Stage 7 — Export

The final `ExecutorResult` is written or exported according to the selected CLI options.

---

## 10. Investigating a Failed Run

If execution fails, troubleshoot in this order.

### Step 1 — Verify Nuclei

```bash
nuclei -version
```

If this fails, fix the Nuclei installation first.

### Step 2 — Verify Python dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Verify the target

```bash
curl -i http://127.0.0.1:8000
```

### Step 4 — Verify the input

Inspect:

```bash
cat suite.json
```

Check:

```text
target
test_cases
endpoint
method
vuln_type
matchers
```

### Step 5 — Check authentication

If the API requires authentication, confirm the expected authentication headers or context are present.

### Step 6 — Check generated template

If the execution reaches template generation but behaves unexpectedly, inspect the generated template and verify:

- URL
- HTTP method
- headers
- request body
- payload
- matcher configuration

### Step 7 — Check Nuclei runtime output

Review stdout/stderr and the raw result data captured by the executor.

---

## 11. Common Problems

### Problem: `nuclei` command not found

Check:

```bash
which nuclei
```

If unavailable:

```bash
export NUCLEI_BIN=/path/to/nuclei
```

Then:

```bash
nuclei -version
```

---

### Problem: Input validation fails

Check that:

```text
target starts with http:// or https://
endpoint starts with /
test_cases is not empty
id is not empty
method is supported
severity is supported
```

The authoritative validation rules are in:

```text
schemas.py
```

---

### Problem: Target returns connection refused

Check the service:

```bash
curl -i http://127.0.0.1:8000
```

Then check the listening port:

Linux:

```bash
ss -lntp
```

Windows:

```powershell
Get-NetTCPConnection -State Listen
```

---

### Problem: No findings are matched

A clean result does not necessarily mean the target is secure.

Check:

1. Is the target reachable?
2. Was the expected endpoint requested?
3. Was authentication valid?
4. Was the intended payload sent?
5. Are the matchers correct?
6. Did the application return the expected response?
7. Is the test case actually applicable to the endpoint?

A matcher that is too restrictive can produce false negatives.

---

### Problem: Too many findings

Review the matcher configuration.

Potential causes include:

- overly broad word matchers
- generic response patterns
- incorrect status matchers
- inappropriate test cases
- application behavior that legitimately matches the detection condition

A `matched=true` result should be reviewed together with its evidence.

---

### Problem: Authentication-dependent tests fail

Verify:

```text
Authorization header
session cookies
API keys
required custom headers
authentication state
```

Do not place real production credentials into committed test specifications.

Use environment-specific secret injection or an approved secret-management mechanism.

---

## 12. Reproducing a Finding

When a finding needs to be reproduced, preserve:

```text
input JSON
target
executor commit
Python version
Nuclei version
generated template
normalized result
raw Nuclei output
authentication context
```

Record the versions:

```bash
python --version
nuclei -version
git rev-parse HEAD
```

Then rerun:

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --output reproduction.json \
  --json
```

Compare:

```text
target
finding ID
matched state
response status
matched_at
evidence
```

A finding should be considered reproducible only when the same test conditions consistently produce equivalent evidence.

---

## 13. Result Triage

Use the following process after execution.

```text
Finding
   │
   ▼
Is the request valid?
   │
   ├── No → Test configuration issue
   │
   └── Yes
        │
        ▼
Did the expected response occur?
        │
        ├── No → Investigate runtime behavior
        │
        └── Yes
             │
             ▼
Does the evidence support the vulnerability hypothesis?
             │
             ├── No → Potential false positive
             │
             └── Yes
                  │
                  ▼
Can the behavior be reproduced?
                  │
                  ├── No → Investigate instability
                  │
                  └── Yes → Valid security finding candidate
```

The executor supplies evidence for this process but does not replace security review.

---

## 14. Safe Operating Procedure

Before every active run:

```text
[ ] Target is authorized
[ ] Target is the intended environment
[ ] API is reachable
[ ] Authentication context is correct
[ ] Input specification is reviewed
[ ] Test cases are appropriate
[ ] Potentially state-changing requests are understood
[ ] Output directory is available
```

After every run:

```text
[ ] Execution completed
[ ] Errors reviewed
[ ] Findings reviewed
[ ] Evidence preserved
[ ] Reproducible findings identified
[ ] Raw/normalized results archived when required
```

---

## 15. Reproducibility Record

For a benchmark or security evaluation, create a record similar to:

```text
Execution ID:
Date:
Target:
Target Environment:
Executor Commit:
Python Version:
Nuclei Version:
Input Specification:
Authentication Context:
Number of Test Cases:
Total Executions:
Matched Findings:
Execution Errors:
Duration:
Result Artifact:
Raw Runtime Artifact:
Notes:
```

This record makes later comparison between executions possible.

---

## 16. Development and Maintenance

When changing the executor:

### Change `schemas.py` when

- the input contract changes
- a new field is introduced
- validation rules change
- output findings change

### Change `template_builder.py` when

- Nuclei template generation changes
- request construction changes
- matcher translation changes

### Change `nuclei_runner.py` when

- Nuclei process handling changes
- executable discovery changes
- runtime arguments change
- stdout/stderr handling changes

### Change `run_nuclei.py` when

- CLI behavior changes
- orchestration changes
- result parsing changes
- export behavior changes

After modifying any of these components, update the relevant tests and documentation.

---

## 17. Operational Checklist

### Setup

```bash
python --version
nuclei -version
pip install -r requirements.txt
```

### Target

```bash
curl -i http://TARGET
```

### Execute

```bash
python -m executor.run_nuclei \
  --input suite.json \
  --output result.json \
  --json
```

### Review

```bash
cat result.json
```

### Archive

Preserve the input specification and result artifacts required for the evaluation.

---

## 18. Component Boundary

Nuclei Executor has one clear operational responsibility:

```text
Structured security test specification
                ↓
        Nuclei execution
                ↓
       normalized findings
```

It should remain independent from higher-level decisions about:

- API discovery
- LLM reasoning
- payload strategy
- vulnerability prioritization
- final vulnerability adjudication
- reporting policy

Those concerns can consume the executor's normalized results without becoming part of the executor itself.

---

## 19. Source of Truth

For operational behavior, use the implementation as the source of truth:

```text
schemas.py
template_builder.py
nuclei_runner.py
run_nuclei.py
```

This runbook documents how to operate the current executor and how to troubleshoot its execution boundary.