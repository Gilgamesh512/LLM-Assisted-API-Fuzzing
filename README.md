# LLM-Assisted API Fuzzing

LLM-assisted API security testing pipeline with context-aware payload generation, schema validation, repair, runtime feedback, Nuclei execution, result normalization, and reproducible experiment evaluation.

> **Scope:** The default benchmark targets are VAmPI, crAPI, and DVGA running locally. Use the pipeline only against systems you own or are explicitly authorized to test.

## 1. Current Architecture

The repository contains several cooperating execution paths. They are related, but they are **not one single command chain**.

```text
                         ┌─────────────────────────────┐
                         │       Target Lab            │
                         │ VAmPI :5002                 │
                         │ crAPI :8888                 │
                         │ DVGA :5013/graphql         │
                         └──────────────┬──────────────┘
                                        │
                          auth + schema │
                                        ▼
                         ┌─────────────────────────────┐
                         │ Schemathesis preparation    │
                         │ run_auth.py                 │
                         │ run_dvga.py                 │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
        ┌────────────────────────────────────────────────────────┐
        │                  Payload generation                    │
        │                                                        │
        │ A. DeepCode Task-B pipeline                            │
        │    analyzer -> api-payload-generator -> validator      │
        │    -> repair -> validated REST payloads                │
        │                                                        │
        │ B. Gemini benchmark generator                          │
        │    REST + GraphQL + Nuclei suite generation            │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │                    Security testing                    │
        │ Schemathesis REST/GraphQL + Nuclei executor             │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │ Results / evaluation                                   │
        │ raw findings -> normalization -> dedup -> summary       │
        │ baseline / security gate / experiment metrics            │
        └────────────────────────────────────────────────────────┘
```

The repository's current target configuration is centralized in `config/targets.yaml`. It declares VAmPI, crAPI, and DVGA, their base URLs, specs, payload outputs, and authentication metadata.

## 2. Repository Layout

```text
LLM-Assisted-API-Fuzzing/
├── core/
│   ├── analyzer.py
│   ├── authorization.py
│   ├── baseline.py
│   ├── deepseek_client.py
│   ├── evaluation.py
│   ├── feedback_loop.py
│   ├── finding.py
│   ├── gemini_client.py
│   ├── manifest.py
│   ├── oracle.py
│   ├── security_checks.py
│   ├── target_config.py
│   ├── telemetry.py
│   └── validator.py
│
├── scripts/
│   ├── run_pipeline.py
│   ├── gen_payloads.py
│   ├── run_feedback_loop.py
│   ├── aggregate_results.py
│   ├── evaluate_experiment.py
│   ├── security_gate.py
│   └── switch_ai.py
│
├── Schemathesis/
│   ├── run_security_tests.py
│   ├── run_schemathesis1.py
│   ├── run_graphql_fuzz1.py
│   ├── run_auth.py
│   ├── run_dvga.py
│   ├── rules_engine.py
│   ├── rules.json
│   ├── payload_rest.json
│   ├── payload_crapi.json
│   ├── payload_graphql.json
│   └── results/
│
├── Nuclei/
│   └── executor/
│       ├── run_nuclei.py
│       ├── nuclei_runner.py
│       ├── schemas.py
│       ├── template_builder.py
│       └── benchmark/
│
├── lab/
│   ├── lab.sh
│   ├── docker-compose.yml
│   └── crapi-compose.yml
│
├── dataset/
├── baseline/
├── results/
├── config/
├── docs/
├── tests/
└── Aegis Agent/
```

`Aegis Agent/` is the local DeepCode CLI source used by the Task-B integration. It is not the fuzzing engine itself.

## 3. Requirements

### Base environment

- Python 3.11-3.13
- Docker
- Docker Compose plugin (`docker compose`)
- `curl`
- `nuclei` in `PATH` when using the Nuclei executor
- Node.js/npm when rebuilding the bundled DeepCode CLI
- DeepCode CLI when using `scripts/run_pipeline.py`
- An LLM provider credential for LLM generation

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -r Schemathesis/requirements.txt
python -m pip install -r Nuclei/executor/requirements.txt
```

Run tests:

```bash
python -m pytest tests/ -v
```

## 4. Target Lab

Start the complete local lab:

```bash
bash lab/lab.sh up
bash lab/lab.sh status
```

Stop it:

```bash
bash lab/lab.sh down
```

The lab launcher starts VAmPI and DVGA from `lab/docker-compose.yml` and downloads/starts the official crAPI compose stack when available.

Expected endpoints:

| Target | Protocol | Base URL |
|---|---|---|
| VAmPI | REST | `http://localhost:5002` |
| crAPI | REST | `http://localhost:8888` |
| DVGA | GraphQL | `http://localhost:5013/graphql` |

The lab uses intentionally vulnerable applications and should remain isolated from production networks.

## 5. Authentication and Schema Preparation

After the lab is running:

```bash
python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py
```

These stages create/update:

```text
Schemathesis/tokens.env
Schemathesis/dvga_schema.json
```

`tokens.env` may contain bearer tokens and must not be committed or printed to shared logs.

## 6. Standard Security-Test Pipeline

The normal Schemathesis security-test controller is:

```bash
python Schemathesis/run_security_tests.py
```

It resolves the current payload corpora, specs, rules, and authentication handoff, then runs:

```text
VAmPI REST
   ↓
crAPI REST
   ↓
DVGA GraphQL
```

The controller writes its detailed findings to:

```text
Schemathesis/results/
├── vulnerabilities.csv
├── vulnerabilities.ndjson
├── experiment_runs.csv
├── state.json
└── state_graphql.json
```

This controller does **not** run Nuclei and does **not** automatically generate new LLM payloads.

## 7. LLM Payload Generation — DeepCode Task-B Pipeline

`scripts/run_pipeline.py` implements the REST-oriented B1-B4 flow:

```text
OpenAPI/Swagger
      ↓
B1: core/analyzer.py
      ↓
context.json
      ↓
B2/B3: DeepCode skill api-payload-generator
      ↓
raw LLM output
      ↓
B4: core/validator.py
      ↓
repair loop (up to 3 attempts)
      ↓
validated payload JSON
      ↓
run manifest
```

Example:

```bash
python scripts/run_pipeline.py path/to/openapi.yaml
```

Custom output:

```bash
python scripts/run_pipeline.py path/to/openapi.yaml \
  --output payloads_validated.json
```

Provider selection:

```bash
python scripts/run_pipeline.py path/to/openapi.yaml \
  --provider gemini
```

The current implementation calls the DeepCode CLI through Node with `shell=False`. This is intentional: generated payload text is passed as an argument rather than through a shell command.

A successful run creates:

```text
context.json
payloads_validated.json
results/runs/<run_id>/manifest.json
```

The validator uses a strict Pydantic contract. Invalid JSON/schema output is repaired automatically and the pipeline stops after the configured maximum of three attempts.

**Important:** this pipeline generates and validates payloads; it does not automatically execute the Schemathesis or Nuclei fuzzers.

## 8. LLM Payload Generation — Benchmark Generator

`scripts/gen_payloads.py` is a separate generator designed for the benchmark corpus.

It can generate:

```text
REST payloads
GraphQL payloads
Nuclei test suites
```

Examples:

```bash
python scripts/gen_payloads.py
python scripts/gen_payloads.py --only rest
python scripts/gen_payloads.py --only graphql
python scripts/gen_payloads.py --target vampi
python scripts/gen_payloads.py --max-endpoints 30
```

This generator currently uses the Gemini client directly and validates the generated REST/GraphQL structures before writing them.

Do not confuse this script with `scripts/run_pipeline.py`:

| Script | Purpose | Provider path | Output |
|---|---|---|---|
| `run_pipeline.py` | Task B1-B4 | DeepCode skill | validated REST payloads |
| `gen_payloads.py` | benchmark generation | Gemini client | REST/GraphQL/Nuclei corpora |

## 9. Nuclei Execution

The Nuclei executor consumes a validated JSON suite:

```text
suite.json
    ↓
Pydantic validation
    ↓
temporary Nuclei templates
    ↓
nuclei
    ↓
JSONL results
    ↓
normalized ExecutorResult
```

Example:

```bash
cd Nuclei/executor

python -m executor.run_nuclei \
  --input benchmark/suite.json \
  --export-dir ../../results/nuclei

cd ../..
```

If Nuclei is not in `PATH`:

```bash
export NUCLEI_BIN=/absolute/path/to/nuclei
```

A test case without a matcher is skipped because the executor cannot determine a meaningful match condition.

The executor does not interpret a Nuclei process return code as proof of a vulnerability. Findings are derived from the emitted JSONL results and matcher evidence.

## 10. Runtime Feedback Loop

The feedback loop is an iterative Nuclei path:

```text
Generation 0
   ↓
Nuclei execution
   ↓
Oracle classification
   ↓
feedback
   ↓
Generation 1
   ↓
...
```

Run:

```bash
python scripts/run_feedback_loop.py
```

The loop stops on successful exploitation, a configured no-progress condition, or the maximum generation budget.

Feedback artifacts are written below:

```text
results/feedback/
```

## 11. Result Aggregation

After Schemathesis and/or Nuclei execution:

```bash
python scripts/aggregate_results.py
```

The aggregator reads supported NDJSON sources, normalizes them into a common finding schema, deduplicates by:

```text
tool
target_app
endpoint
method
vuln_type
```

and writes:

```text
results/findings_summary.csv
results/findings_summary.ndjson
```

The unified summary is the preferred cross-engine result for analysis.

## 12. Confirmation Semantics

The project distinguishes between a candidate signal and a confirmed finding.

Examples of strong signals include:

- an explicit matcher hit;
- expected security evidence in a response;
- reproducible behavior across the confirmation logic;
- authorization tests where the unauthorized identity actually receives access.

The following should not be treated as automatic proof by themselves:

```text
HTTP 5xx
generic "error" / "exception" text
a GraphQL error response
a CVE keyword match
```

The oracle and finding normalization layers preserve this distinction so that candidate findings are not silently counted as confirmed vulnerabilities.

## 13. Authorization Checks

`core/authorization.py` provides reusable checks for:

- missing/invalid/expired authentication;
- BOLA;
- BFLA;
- dependent stateful workflows.

These checks are library components. They are not automatically invoked by `Schemathesis/run_security_tests.py` unless an execution path explicitly calls them.

## 14. Baseline and Security Gate

Baseline comparison is implemented in `core/baseline.py`.

The baseline key is:

```text
target_app + method + endpoint + vulnerability
```

The security gate can fail a run when findings meet or exceed a severity threshold.

Example:

```bash
python scripts/security_gate.py --input results/findings_summary.ndjson --fail-on high
```

Use the exact CLI help of the current script if options are changed:

```bash
python scripts/security_gate.py --help
```

## 15. Reproducible Evaluation

Experiment evaluation is implemented in:

```text
core/evaluation.py
scripts/evaluate_experiment.py
```

The intended comparison arms are:

| Treatment | Generator | Validation | Feedback |
|---|---|---:|---:|
| B0 | Schemathesis default | No | No |
| B1 | Schemathesis + handcrafted payload | No | No |
| P0 | LLM | No | No |
| P1 | LLM | Yes | No |
| P2 | LLM | Yes | Yes |

For fair comparisons, keep the target, endpoint set, timeout, run count, seed, schema/context hash, and relevant model/provider settings fixed.

The evaluator reports metrics including payload validity, executability, uniqueness, confirmed findings, detection rate, false-positive rate, runtime, and LLM cost fields when the required telemetry is available.

## 16. Run Manifests and Telemetry

Generation runs use a versioned manifest contract:

```text
config/manifest.schema.json
```

Manifests record:

- run ID;
- target/protocol;
- provider/model;
- token usage when exposed by the provider;
- repair count and repair success;
- stage timings;
- payload count;
- context/output artifact paths.

Current DeepCode subprocess integration only receives stdout. Therefore token usage may remain unavailable/zero in manifests. Runtime must not be used to estimate token usage.

## 17. AI Provider Configuration

The repository currently ships a `.deepcode/providers.json` containing a Gemini provider profile.

Check the current provider list:

```bash
python scripts/switch_ai.py status
```

Switch to an available provider:

```bash
python scripts/switch_ai.py gemini
```

Provider keys belong in `.env` or user-level DeepCode settings, never in committed source.

Example:

```text
GEMINI_API_KEY=<your-key>
```

Do not assume that `deepseek` is available merely because older documentation mentions it. The current provider registry is authoritative.

## 18. Security and Operational Rules

Never commit:

```text
.env
tokens.env
API keys
bearer tokens
sensitive response bodies
private benchmark evidence
```

Only use authorized targets.

Before changing a target, review:

```text
config/targets.yaml
```

The configuration currently allows only:

```text
vampi
crapi
dvga
```

Do not enable a production target merely by copying the commented example without reviewing authorization, authentication, rate limits, and data-handling requirements.

## 19. Recommended Operator Workflows

### Full local benchmark

```bash
python -m pip install -r requirements.txt
python -m pip install -r Schemathesis/requirements.txt
python -m pip install -r Nuclei/executor/requirements.txt

bash lab/lab.sh up
bash lab/lab.sh status

python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py

python scripts/gen_payloads.py
python Schemathesis/run_security_tests.py

cd Nuclei/executor
python -m executor.run_nuclei \
  --input benchmark/suite.json \
  --export-dir ../../results/nuclei
cd ../..

python scripts/aggregate_results.py
```

### DeepCode Task-B experiment

```bash
python scripts/switch_ai.py status
python scripts/run_pipeline.py dataset/vampi_openapi.json \
  --provider gemini \
  --output results/payloads_vampi.json
```

Then explicitly hand the validated payload artifact to the appropriate fuzzing engine. Generation and execution are intentionally separate.

### Reproducibility experiment

1. Fix the target and endpoint set.
2. Fix timeout, seed, and run count.
3. Record provider/model and prompt version.
4. Record the schema/context hash.
5. Store payload and findings artifacts.
6. Create an experiment manifest.
7. Run `scripts/evaluate_experiment.py`.
8. Compare treatments only after normalization and confirmation filtering.

## 20. Troubleshooting

### `run_security_tests.py` reports missing payloads

Check:

```bash
ls Schemathesis/payload_rest.json
ls Schemathesis/payload_crapi.json
ls Schemathesis/payload_graphql.json
```

If they are absent, generate or restore the expected payload artifacts before running the controller.

### Authentication is missing

Run:

```bash
python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py
```

Then verify only the variable names:

```bash
grep -E '^export .*AUTH_HEADER=' Schemathesis/tokens.env \
  | sed 's/=.*/=<redacted>/'
```

### Nuclei is not found

```bash
nuclei -version
```

or:

```bash
export NUCLEI_BIN=/absolute/path/to/nuclei
```

### DeepCode is not found

Verify the local DeepCode CLI installation/build and rebuild the `Aegis Agent/` source when required:

```bash
cd "Aegis Agent"
npm install
npm run build
cd ..
```

### LLM output fails validation

Inspect the validation error and repair count in the run output/manifest. The Task-B pipeline intentionally stops after three attempts.

### Aggregated results are empty

Check that the expected NDJSON inputs exist:

```bash
find Schemathesis/results Nuclei/executor/results results/nuclei \
  -name '*.ndjson' -print
```

## 21. Current Documentation Debt

The current repository still contains older wording that should be removed or corrected.

### Must fix

1. `Schemathesis/run_security_tests.py` still prints `main_pipeline` and `legacy pipeline` terminology although the repository has moved the active scripts to `Schemathesis/`.
2. `Schemathesis/README.md` and `Schemathesis/RUNBOOK.md` describe the old standalone layout and should be replaced with documentation that treats `config/targets.yaml` and the repository-root lab as authoritative.
3. `docs/USAGE.md` contains older DeepCode setup instructions and should not be the source of truth for the current provider registry.
4. `scripts/switch_ai.py` documentation mentions DeepSeek, but the committed `.deepcode/providers.json` currently exposes only Gemini. Documentation should follow the provider registry.
5. The root README previously presented the whole repository as one linear pipeline. The implementation actually contains separate generation, fuzzing, feedback, aggregation, and evaluation flows.
6. `config/targets.yaml` is described as the single target source, but some legacy/compatibility logic still exists in downstream scripts. Prefer `config/targets.yaml` as the operator-facing source of truth.
7. `Schemathesis` runtime artifacts and root `results/` have different ownership. The documentation must keep those paths distinct.
8. `gen_payloads.py` and `run_pipeline.py` are not interchangeable and should remain documented as separate workflows.

## 22. Source-of-Truth Rules

When documentation conflicts with implementation, use this order:

```text
1. Current executable code
2. config/targets.yaml
3. current manifest/schema contracts
4. current provider registry
5. README/RUNBOOK
6. historical reports and old task notes
```

This keeps the documentation aligned with the repository rather than preserving historical assumptions.
