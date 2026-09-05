### Dry run (individual commands) ###
# Remember to `source .venv/bin/activate` every time you open a new terminal, before running any script
cd ~/LLM-Assisted-API-Fuzzing
source .venv/bin/activate
ls


# Make scripts executable
cd ~/LLM-Assisted-API-Fuzzing/Schemathesis
chmod +x run_all.py start_lab.py run_auth.py run_dvga.py \
         run_schemathesis1.py run_graphql_fuzz1.py rules_engine.py run_security_tests.py

# Refresh the CVE cache (run periodically, e.g. once a week via cron) - requires real internet access
python3 rules_engine.py --update --rules rules.json --days 30


# REST API
# VAmPI
export FUZZ_AUTH_HEADER=$VAMPI_AUTH_HEADER
python3 run_schemathesis1.py \
  --targets "vampi=vampi_spec.yaml" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads payload_rest.json \
  --rules rules.json \
  --concurrency 5

# crAPI
export FUZZ_AUTH_HEADER=$CRAPI_AUTH_HEADER
python3 run_schemathesis1.py \
  --targets "crapi=crapi_spec.yaml" \
  --base-urls "crapi=http://localhost:8888" \
  --payloads payload_crapi.json \
  --rules rules.json \
  --concurrency 5


# GraphQL: DVGA
export FUZZ_AUTH_HEADER=$DVGA_AUTH_HEADER
python3 run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --payloads payload_graphql.json \
  --rules rules.json \
  --concurrency 5

# View results
cat results/vulnerabilities.csv
cat results/vulnerabilities.ndjson


### Run the pipeline ###
# Remember to `source .venv/bin/activate` every time you open a new terminal, before running any script
cd ~/LLM-Assisted-API-Fuzzing
source .venv/bin/activate


# Option 1 — Fuzzing only (lab already running + tokens still valid)
cd ~/LLM-Assisted-API-Fuzzing
python3 Schemathesis/run_security_tests.py


# Option 2 — Fetch all 3 tokens first, then fuzz (lab already running, only tokens expired)
cd ~/LLM-Assisted-API-Fuzzing
python3 Schemathesis/run_auth.py      # gets VAMPI_AUTH_HEADER + CRAPI_AUTH_HEADER -> tokens.env
python3 Schemathesis/run_dvga.py      # gets DVGA_AUTH_HEADER + dvga_schema.json  -> tokens.env
python3 Schemathesis/run_security_tests.py


# Option 3 — Run everything end to end, single command
cd ~/LLM-Assisted-API-Fuzzing
python3 Schemathesis/run_all.py
