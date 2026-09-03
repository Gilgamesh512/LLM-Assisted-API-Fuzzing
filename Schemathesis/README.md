# Main API Fuzzing Pipeline

Main security-testing pipeline for the API fuzzing lab. This pipeline prepares the target applications, obtains authentication tokens, discovers the DVGA GraphQL schema, and then runs the main REST + GraphQL fuzzing stages.

The current Main pipeline is intentionally separated from the legacy DVGA pipeline. The Main controller does **not** execute the legacy DVGA fuzzer or its analyze/triage chain.

## Pipeline

```text
run_all.py
    |
    +--> start_lab.py
    |       +--> VAmPI
    |       +--> crAPI
    |       +--> DVGA
    |
    +--> run_auth.py
    |       +--> VAMPI_AUTH_HEADER
    |       +--> CRAPI_AUTH_HEADER
    |
    +--> run_dvga.py
    |       +--> DVGA_AUTH_HEADER
    |       +--> dvga_schema.json
    |
    +--> validate handoff
    |       +--> tokens.env
    |       +--> dvga_schema.json
    |
    +--> run_security_tests.py
            |
            +--> run_schemathesis1.py
            |       +--> VAmPI REST fuzzing
            |       +--> crAPI REST fuzzing
            |       +--> results/vulnerabilities.csv
            |       +--> results/vulnerabilities.ndjson
            |       +--> results/experiment_runs.csv
            |
            +--> run_graphql_fuzz1.py
                    +--> DVGA GraphQL fuzzing
                    +--> results/vulnerabilities.csv
                    +--> results/vulnerabilities.ndjson
                    +--> results/experiment_runs.csv
```

## Targets

| Target | Protocol | Base URL | Main component |
|---|---|---|---|
| VAmPI | REST | `http://localhost:5002` | `run_schemathesis1.py` |
| crAPI | REST | `http://localhost:8888` | `run_schemathesis1.py` |
| DVGA | GraphQL | `http://localhost:5013/graphql` | `run_graphql_fuzz1.py` |

The target lab is started by `start_lab.py`.

Expected local target locations:

```text
~/VAmPI
~/crAPI
~/Damn-Vulnerable-GraphQL-Application
```

VAmPI and crAPI are started with Docker Compose. DVGA is built into a Docker image named `dvga` and started with port `5013` exposed.

## Project structure

```text
main_pipeline/
├── run_all.py
├── start_lab.py
├── run_auth.py
├── run_dvga.py
├── run_security_tests.py
├── run_schemathesis1.py
├── run_graphql_fuzz1.py
├── rules_engine.py
│
├── payload_rest.json
├── payload_crapi.json
├── payload_graphql.json
├── vampi_spec.yaml
├── vampi_spec.json
├── crapi_openapi_spec.json
├── crapi_spec.yaml
├── rules.json
│
├── tokens.env
├── dvga_schema.json
│
└── results/
    ├── vulnerabilities.csv
    ├── vulnerabilities.ndjson
    ├── experiment_runs.csv
    ├── state.json
    └── state_graphql.json
```

`tokens.env`, `dvga_schema.json`, and files under `results/` are runtime artifacts produced or updated by the pipeline.

## Requirements

Use the project's Python virtual environment before running the pipeline:

```bash
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate
```

The fuzzers require the following Python packages:

```bash
pip install schemathesis pydantic httpx pyyaml requests
```

The lab also requires Docker/Docker Compose and the three target applications at the paths expected by `start_lab.py`.

## Run

### Option 1 — Run the complete pipeline

From the project root:

```bash
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate

python3 main_pipeline/run_all.py
```

This is the recommended execution path.

It performs:

1. Check the Main pipeline files.
2. Start VAmPI, crAPI, and DVGA.
3. Authenticate VAmPI and crAPI.
4. Create a temporary DVGA user, authenticate, and obtain a JWT.
5. Run GraphQL introspection against DVGA.
6. Save the DVGA schema.
7. Validate the authentication/schema handoff.
8. Run the main REST and GraphQL fuzzers.
9. Write the results under `main_pipeline/results/`.

## Run individual stages

### Start the target lab

```bash
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate

python3 main_pipeline/start_lab.py
```

This starts:

- VAmPI on `localhost:5002`
- crAPI on `localhost:8888`
- DVGA on `localhost:5013`

### Authenticate VAmPI + crAPI

```bash
python3 main_pipeline/run_auth.py
```

The script creates/logs into the configured test accounts and writes:

```text
main_pipeline/tokens.env
```

with:

```text
VAMPI_AUTH_HEADER
CRAPI_AUTH_HEADER
```

The file is written with restrictive permissions where supported.

### Authenticate + discover DVGA

```bash
python3 main_pipeline/run_dvga.py
```

This stage:

- waits for DVGA;
- creates a unique temporary user;
- logs in through the GraphQL `login` mutation;
- stores `DVGA_AUTH_HEADER` in `tokens.env`;
- runs GraphQL introspection;
- saves the discovered schema to `dvga_schema.json`.

The generated schema contains both the raw introspection result and a short analysis including query type, mutation type, total types, queries, and mutations.

### Run the main security-testing pipeline only

If the lab is already running and the authentication artifacts are still valid:

```bash
python3 main_pipeline/run_security_tests.py
```

This runs:

```text
VAmPI REST
    ↓
crAPI REST
    ↓
DVGA GraphQL
```

The controller reads the authentication headers from `tokens.env` and passes each target's header to its corresponding fuzzing stage.

## Fuzzing components

### REST — VAmPI and crAPI

`run_schemathesis1.py` integrates Schemathesis with the generated payload corpus.

The runner uses:

- OpenAPI specifications;
- JSON payload corpora;
- `rules.json`;
- authentication from `FUZZ_AUTH_HEADER`;
- fingerprint-based deduplication;
- persistent state in `state.json`;
- result logging under `results/`.

Example VAmPI execution:

```bash
python3 main_pipeline/run_schemathesis1.py \
  --targets "vampi=main_pipeline/vampi_spec.yaml" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads main_pipeline/payload_rest.json \
  --rules rules.json \
  --results-dir main_pipeline/results \
  --concurrency 3
```

Example crAPI execution:

```bash
python3 main_pipeline/run_schemathesis1.py \
  --targets "crapi=main_pipeline/crapi_openapi_spec.json" \
  --base-urls "crapi=http://localhost:8888" \
  --payloads main_pipeline/payload_crapi.json \
  --rules rules.json \
  --results-dir main_pipeline/results \
  --concurrency 3
```

Authentication is normally injected by `run_security_tests.py` from `tokens.env`.

### GraphQL — DVGA

`run_graphql_fuzz1.py` sends the generated GraphQL payloads to DVGA.

Example:

```bash
python3 main_pipeline/run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --payloads main_pipeline/payload_graphql.json \
  --rules rules.json \
  --results-dir main_pipeline/results \
  --concurrency 3
```

The GraphQL endpoint defaults to:

```text
/graphql
```

so the effective target is:

```text
http://localhost:5013/graphql
```

Authentication can be supplied through:

```text
FUZZ_AUTH_HEADER
```

or the script's `--auth-header` option.

## Authentication handoff

The Main pipeline uses one shared handoff file:

```text
main_pipeline/tokens.env
```

Expected authentication headers:

```text
VAMPI_AUTH_HEADER
CRAPI_AUTH_HEADER
DVGA_AUTH_HEADER
```

The normal flow is:

```text
run_auth.py
    ├── VAmPI token
    └── crAPI token
            |
            v
        tokens.env

run_dvga.py
    ├── DVGA token
    └── DVGA schema
            |
            v
        tokens.env + dvga_schema.json

run_security_tests.py
    |
    +── VAMPI_AUTH_HEADER -> VAmPI
    +── CRAPI_AUTH_HEADER -> crAPI
    └── DVGA_AUTH_HEADER  -> DVGA
```

`run_all.py` validates that all three authentication headers and a valid DVGA GraphQL schema exist before launching the security-testing stage.

## Rules and CVE updates

`rules_engine.py` manages the shared rule data.

To inspect the current rule state:

```bash
python3 main_pipeline/rules_engine.py --rules rules.json
```

To update the CVE cache from the NVD API:

```bash
python3 main_pipeline/rules_engine.py \
  --update \
  --rules rules.json \
  --days 30
```

For example, using an NVD API key:

```bash
python3 main_pipeline/rules_engine.py \
  --update \
  --rules rules.json \
  --days 90 \
  --api-key <NVD_API_KEY>
```

The default CVE search focuses on API-security-related keywords such as:

```text
REST API injection
JWT authentication bypass
GraphQL injection
SQL injection API
SSRF
mass assignment
broken object level authorization
```

CVE matches are contextual signals. A CVE keyword match is **not** by itself proof that the target is vulnerable to that CVE.

## Results

The main pipeline writes results to:

```text
main_pipeline/results/
```

### `vulnerabilities.csv`

Tabular finding output containing fields such as:

```text
run_id
timestamp
target_app
endpoint
method
attack_type
owasp_category
payload
status_code
response_time_ms
evidence
severity
confirmed
fingerprint
matched_cve
```

### `vulnerabilities.ndjson`

Line-delimited JSON representation of findings. GraphQL findings are marked with:

```text
source = graphql
```

### `experiment_runs.csv`

Run-level statistics, including:

```text
run_id
timestamp
tool
targets
total_payloads
total_fired
total_skipped_dedup
total_confirmed
llm_used
```

### State files

```text
state.json
state_graphql.json
```

These keep fingerprint/deduplication state between runs.

## Finding confirmation

The fuzzers do not treat every error response as a confirmed vulnerability.

In particular:

- expected payload-specific signals are used as primary confirmation evidence;
- server-side `5xx` responses are treated as strong signals;
- generic strings such as `debug`, `exception`, or `error` alone are not sufficient to confirm a vulnerability;
- GraphQL errors alone are not automatically vulnerabilities;
- matched CVEs provide contextual information and are not proof of exploitation.

This distinction is important for reducing false positives.

## Ownership boundary

The Main pipeline owns:

```text
start_lab.py
run_auth.py
run_dvga.py
run_security_tests.py
run_schemathesis1.py
run_graphql_fuzz1.py
rules_engine.py
```

The legacy DVGA pipeline is intentionally independent.

The Main pipeline does **not** execute:

```text
run_dvga_fuzzer.py
```

and does not depend on the legacy DVGA analyze/triage workflow.

## Security / runtime notes

### `tokens.env`

This file contains authentication material. Do not commit it to source control.

The pipeline attempts to set restrictive file permissions (`0600`) when the operating system permits it.

### Results

Previous result files may contain application responses and other sensitive runtime data. Treat the `results/` directory as test-environment data rather than source code.

### Target environment

This pipeline is designed for the local vulnerable applications used by the lab:

```text
VAmPI
crAPI
DVGA
```

Do not point the fuzzers at systems you do not have explicit authorization to test.

## Quick reference

### Full run

```bash
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate
python3 main_pipeline/run_all.py
```

### Refresh tokens + schema, then fuzz

```bash
python3 main_pipeline/run_auth.py
python3 main_pipeline/run_dvga.py
python3 main_pipeline/run_security_tests.py
```

### Fuzz only

```bash
python3 main_pipeline/run_security_tests.py
```

### Update CVE rules

```bash
python3 main_pipeline/rules_engine.py \
  --update \
  --rules rules.json \
  --days 30
```

### View results

```bash
cat main_pipeline/results/vulnerabilities.csv
cat main_pipeline/results/vulnerabilities.ndjson
```

## Legacy pipeline

The legacy DVGA pipeline is maintained separately and should not be mixed with this Main pipeline.

Its role and excluded components are documented in the legacy README. The Main pipeline is the active controller for the VAmPI + crAPI REST and DVGA GraphQL security-testing flow.
