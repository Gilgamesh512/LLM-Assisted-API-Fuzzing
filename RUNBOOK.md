# LLM-Assisted API Fuzzing — Operator Runbook

This runbook describes the current operational workflow of the repository as implemented on `main`.

> Use only against VAmPI, crAPI, DVGA, or another explicitly authorized target.

## 1. Standard Environment

From the repository root:

```bash
cd ~/LLM-Assisted-API-Fuzzing
```

Create/activate a virtual environment if desired:

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r Schemathesis/requirements.txt
python -m pip install -r Nuclei/executor/requirements.txt
```

Verify:

```bash
python --version
docker --version
docker compose version
curl --version
nuclei -version
```

Run tests before a major experiment:

```bash
python -m pytest tests/ -v
```

## 2. Pre-Flight Checklist

Confirm the repository is clean enough for the intended run:

```bash
git status --short
```

Confirm target configuration:

```bash
cat config/targets.yaml
```

Do not put secrets into `config/targets.yaml`.

Confirm the expected target set:

```text
vampi
crapi
dvga
```

Confirm no secrets are staged:

```bash
git status --short
```

## 3. Start the Lab

Start all local targets:

```bash
bash lab/lab.sh up
```

Check readiness:

```bash
bash lab/lab.sh status
```

Expected services:

```text
VAmPI  -> http://localhost:5002
crAPI  -> http://localhost:8888
DVGA   -> http://localhost:5013
```

Basic checks:

```bash
curl -i http://localhost:5002
curl -i http://localhost:8888
curl -i http://localhost:5013
```

A reachable HTTP response is a connectivity check, not a complete application-health test.

## 4. Prepare Authentication

Run:

```bash
python Schemathesis/run_auth.py
```

Expected artifact:

```text
Schemathesis/tokens.env
```

Verify only variable names:

```bash
grep -E '^export (VAMPI_AUTH_HEADER|CRAPI_AUTH_HEADER)=' \
  Schemathesis/tokens.env | sed 's/=.*/=<redacted>/'
```

Never print the token values.

## 5. Prepare DVGA

Run:

```bash
python Schemathesis/run_dvga.py
```

Expected artifacts:

```text
Schemathesis/tokens.env
Schemathesis/dvga_schema.json
```

Validate the schema metadata:

```bash
python - <<'PY'
import json
from pathlib import Path

p = Path("Schemathesis/dvga_schema.json")
if not p.exists():
    raise SystemExit("dvga_schema.json is missing")

data = json.loads(p.read_text(encoding="utf-8"))
print("target   :", data.get("target"))
print("protocol :", data.get("protocol"))
print("graphql  :", data.get("graphql_url"))
PY
```

Expected protocol:

```text
graphql
```

## 6. Generate Benchmark Payloads

For the current Gemini benchmark generator:

```bash
python scripts/gen_payloads.py
```

Useful restricted runs:

```bash
python scripts/gen_payloads.py --only rest
python scripts/gen_payloads.py --only graphql
python scripts/gen_payloads.py --target vampi
python scripts/gen_payloads.py --max-endpoints 30
```

Before generation, ensure the required LLM credential is available:

```bash
grep '^GEMINI_API_KEY=' .env | sed 's/=.*/=<redacted>/'
```

Do not echo the real key.

## 7. Run the Main Schemathesis Security Controller

Run:

```bash
python Schemathesis/run_security_tests.py
```

The controller:

1. resolves the configured specs;
2. resolves REST and GraphQL payload corpora;
3. loads `Schemathesis/rules.json`;
4. reads authentication artifacts if present;
5. runs VAmPI REST fuzzing;
6. runs crAPI REST fuzzing;
7. runs DVGA GraphQL fuzzing.

It does not run Nuclei.

## 8. Inspect Schemathesis Results

Expected files:

```text
Schemathesis/results/vulnerabilities.csv
Schemathesis/results/vulnerabilities.ndjson
Schemathesis/results/experiment_runs.csv
Schemathesis/results/state.json
Schemathesis/results/state_graphql.json
```

Quick checks:

```bash
ls -lh Schemathesis/results/
```

Count findings:

```bash
python - <<'PY'
import csv
from pathlib import Path

p = Path("Schemathesis/results/vulnerabilities.csv")
if not p.exists():
    raise SystemExit("No Schemathesis findings file")

with p.open(newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))

confirmed = [
    r for r in rows
    if str(r.get("confirmed", "")).lower() == "true"
]

print("total findings:", len(rows))
print("confirmed     :", len(confirmed))
PY
```

## 9. Run Nuclei

Use the generated/selected suite:

```bash
cd Nuclei/executor

python -m executor.run_nuclei \
  --input benchmark/suite.json \
  --export-dir ../../results/nuclei

cd ../..
```

If the binary is not on `PATH`:

```bash
export NUCLEI_BIN=/absolute/path/to/nuclei
```

Optional template validation:

```bash
nuclei -t Nuclei/executor/benchmark -validate
```

The executor creates temporary templates, executes Nuclei, maps matches back to test-case IDs, and exports normalized findings.

## 10. Aggregate Cross-Engine Results

Run:

```bash
python scripts/aggregate_results.py
```

Expected output:

```text
results/findings_summary.csv
results/findings_summary.ndjson
```

Inspect:

```bash
column -s, -t < results/findings_summary.csv | less -S
less results/findings_summary.ndjson
```

The aggregator deduplicates by:

```text
tool + target_app + endpoint + method + vuln_type
```

Do not interpret a deduplicated row as an independent confirmation from every engine.

## 11. Run the DeepCode Task-B Pipeline

This is a separate payload-generation workflow.

Example:

```bash
python scripts/run_pipeline.py dataset/vampi_openapi.json \
  --provider gemini \
  --output results/payloads_vampi.json
```

Execution stages:

```text
B1 analyzer
   ↓
context.json
   ↓
B2/B3 DeepCode skill
   ↓
raw LLM output
   ↓
B4 validator
   ↓
repair loop
   ↓
validated payloads
   ↓
manifest
```

Expected artifacts:

```text
context.json
results/payloads_vampi.json
results/runs/<run_id>/manifest.json
```

The pipeline does not automatically fuzz the target after generation.

## 12. Validate a Generated Payload Artifact

For the Task-B payload contract, use the validator before handing the artifact to a fuzzing engine.

The validated schema contains fields such as:

```text
method
path
target_parameter
location
vulnerability_type
payload_value
rationale
expected_indicator
```

The validator rejects unexpected fields and invalid enum values.

## 13. Provider Management

Check the configured provider:

```bash
python scripts/switch_ai.py status
```

Switch to the provider currently registered in `.deepcode/providers.json`:

```bash
python scripts/switch_ai.py gemini
```

Do not use:

```bash
python scripts/switch_ai.py deepseek
```

unless a `deepseek` entry has first been added to `.deepcode/providers.json`.

The current committed provider registry exposes Gemini.

## 14. Feedback-Guided Nuclei Loop

Run:

```bash
python scripts/run_feedback_loop.py
```

Operational model:

```text
generate suite
    ↓
execute Nuclei
    ↓
oracle classification
    ↓
runtime feedback
    ↓
generate next suite
```

The loop has generation and no-progress limits. It is not the default path of `run_security_tests.py`.

Check:

```bash
find results/feedback -maxdepth 2 -type f -print
```

## 15. Baseline Comparison

Baseline comparison is implemented in:

```text
core/baseline.py
```

The comparison distinguishes:

```text
new
resolved
unchanged
```

The identity key uses:

```text
target_app
method
endpoint
vulnerability
```

Do not compare runs with different endpoint sets and call the difference a regression.

## 16. Security Gate

Inspect CLI options:

```bash
python scripts/security_gate.py --help
```

The underlying gate is severity-based. The default threshold in `core/baseline.py` is `high`.

Conceptually:

```text
no finding >= threshold -> PASS
finding >= threshold    -> FAIL
```

Use this as a release/experiment gate only after the findings have been normalized and confirmed according to the project's evidence model.

## 17. Experiment Evaluation

Prepare a JSON experiment manifest containing comparable runs and their payload/finding artifacts.

Then:

```bash
python scripts/evaluate_experiment.py \
  path/to/experiment_manifest.json \
  --output results/experiment_metrics.json
```

Keep these controlled:

```text
target
endpoint set
timeout
number of runs
seed
schema/context hash
provider
model
prompt version
temperature
```

The evaluator reports metrics including:

```text
valid_payload_rate
executability_rate
unique_payload_rate
confirmed_findings
detection_rate
false_positive_rate
runtime_seconds
llm_cost_usd
```

If provider token usage is unavailable, do not infer token usage from runtime.

## 18. Manual REST Fuzzing

VAmPI:

```bash
export FUZZ_AUTH_HEADER="$(grep '^export VAMPI_AUTH_HEADER=' \
  Schemathesis/tokens.env | sed 's/^export VAMPI_AUTH_HEADER=//')"

python Schemathesis/run_schemathesis1.py \
  --targets "vampi=dataset/vampi_openapi.json" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads Schemathesis/payload_rest.json \
  --rules Schemathesis/rules.json \
  --results-dir Schemathesis/results \
  --concurrency 3
```

crAPI:

```bash
export FUZZ_AUTH_HEADER="$(grep '^export CRAPI_AUTH_HEADER=' \
  Schemathesis/tokens.env | sed 's/^export CRAPI_AUTH_HEADER=//')"

python Schemathesis/run_schemathesis1.py \
  --targets "crapi=Schemathesis/crapi_openapi_spec.json" \
  --base-urls "crapi=http://localhost:8888" \
  --payloads Schemathesis/payload_crapi.json \
  --rules Schemathesis/rules.json \
  --results-dir Schemathesis/results \
  --concurrency 3
```

For normal operation, prefer `run_security_tests.py`, which injects the appropriate token per target.

## 19. Manual GraphQL Fuzzing

```bash
export FUZZ_AUTH_HEADER="$(grep '^export DVGA_AUTH_HEADER=' \
  Schemathesis/tokens.env | sed 's/^export DVGA_AUTH_HEADER=//')"

python Schemathesis/run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --payloads Schemathesis/payload_graphql.json \
  --rules Schemathesis/rules.json \
  --results-dir Schemathesis/results \
  --concurrency 3
```

The current runner filename is:

```text
run_graphql_fuzz1.py
```

## 20. Rules / CVE Maintenance

Inspect rules:

```bash
python Schemathesis/rules_engine.py \
  --rules Schemathesis/rules.json
```

Update the cache:

```bash
python Schemathesis/rules_engine.py \
  --update \
  --rules Schemathesis/rules.json \
  --days 30
```

If using an NVD API key, keep it outside the repository and follow the current CLI help.

A CVE match is context, not proof of exploitability.

## 21. Troubleshooting

### Target lab is not ready

```bash
bash lab/lab.sh status
docker ps
```

Restart:

```bash
bash lab/lab.sh down
bash lab/lab.sh up
```

### crAPI was skipped by `lab.sh`

The lab script downloads the upstream crAPI compose file. If download fails, follow `lab/README.md` and run the compose stack manually.

### Payload corpus missing

```bash
ls Schemathesis/payload_rest.json
ls Schemathesis/payload_crapi.json
ls Schemathesis/payload_graphql.json
```

Generate/restore the missing corpus before starting fuzzing.

### Auth artifacts missing

```bash
python Schemathesis/run_auth.py
python Schemathesis/run_dvga.py
```

### Nuclei missing

```bash
nuclei -version
echo "$NUCLEI_BIN"
```

### DeepCode missing

Rebuild the local source:

```bash
cd "Aegis Agent"
npm install
npm run build
cd ..
```

Then verify the CLI according to the installed DeepCode distribution.

### Task-B output remains invalid

Inspect the validator error. The automatic repair loop has a maximum of three attempts. If it still fails, preserve the run output and manifest rather than silently continuing with unvalidated payloads.

### Results appear in an unexpected directory

When invoking a runner directly, pass an explicit result directory:

```bash
--results-dir Schemathesis/results
```

For Nuclei:

```bash
--export-dir results/nuclei
```

## 22. Cleanup

Stop the target lab:

```bash
bash lab/lab.sh down
```

Reset runtime artifacts only when intentionally starting a new experiment:

```bash
rm -rf results/*
rm -rf Schemathesis/results/*
rm -f Schemathesis/tokens.env
```

Do not remove:

```text
config/
dataset/
Schemathesis/rules.json
Schemathesis/*.py
core/
scripts/
Nuclei/executor/
```

unless you intentionally want to change the implementation or benchmark.

## 23. Successful Run Criteria

A standard benchmark run is considered operationally complete when:

```text
[ ] lab targets are reachable
[ ] authentication artifacts were refreshed when required
[ ] DVGA schema is present
[ ] payload corpora exist
[ ] Schemathesis REST stages completed
[ ] Schemathesis GraphQL stage completed
[ ] Nuclei stage completed if selected
[ ] normalized summary exists
[ ] candidate vs confirmed status has been reviewed
[ ] experiment manifest exists for reproducibility
[ ] lab has been stopped after testing
```

For a full cross-engine benchmark, verify:

```text
results/findings_summary.csv
results/findings_summary.ndjson
```

and retain the raw engine-specific artifacts needed to reproduce the findings.

## 24. Documentation / Code Drift to Track

The following items are current implementation/documentation inconsistencies and should be treated as maintenance tasks:

1. `Schemathesis/run_security_tests.py` still prints old `main_pipeline` / `legacy pipeline` terminology.
2. The old `Schemathesis/README.md` and `Schemathesis/RUNBOOK.md` should no longer describe a standalone legacy/main split.
3. `docs/USAGE.md` contains historical DeepCode instructions and should be updated to match the current provider registry and repository layout.
4. `.deepcode/providers.json` currently contains Gemini only, while `switch_ai.py` text still describes DeepSeek as available.
5. `config/targets.yaml` should remain the operator-facing target source of truth.
6. The root `results/` directory and `Schemathesis/results/` are different artifact domains and should not be conflated.
7. `scripts/run_pipeline.py` is payload generation/validation, not a full fuzzing pipeline.
8. `scripts/gen_payloads.py` is a separate benchmark generator and should not be described as the same pipeline as `run_pipeline.py`.
