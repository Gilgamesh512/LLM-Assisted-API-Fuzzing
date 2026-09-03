### Chạy chay ###
# Nhớ source ~/fuzzenv/bin/activate mỗi lần mở terminal mới trước khi chạy script
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate
ls


# Cấp quyền thực thi
cd ~/fuzzing-tool/main_pipeline
chmod +x run_all.py start_lab.py run_auth.py run_dvga.py \
         run_schemathesis1.py run_graphql_fuzz1.py rules_engine.py run_security_tests.py

# Cập nhật CVE mới nhất (chạy định kỳ, vd cron 1 lần/tuần) - cần internet thật
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
python3 run_graphql_fuzz.py \
  --base-url http://localhost:5013 \
  --payloads payload_graphql.json \
  --rules rules.json \
  --concurrency 5

# Xem kết quả
cat results/vulnerabilities.csv
cat results/vulnerabilities.ndjson


### Chạy Pipeline ###
# Nhớ source ~/fuzzenv/bin/activate mỗi lần mở terminal mới trước khi chạy script
cd ~/fuzzing-tool
source ~/fuzzenv/bin/activate


# Cách 1 — Chỉ chạy fuzzing (khi lab đã chạy sẵn + token còn hạn)
cd ~/fuzzing-tool
python3 main_pipeline/run_security_tests.py


# Cách 2 — Lấy 3 token trước, rồi mới fuzz (lab đã chạy sẵn, chỉ token hết hạn)
cd ~/fuzzing-tool
python3 main_pipeline/run_auth.py      # lấy VAMPI_AUTH_HEADER + CRAPI_AUTH_HEADER -> tokens.env
python3 main_pipeline/run_dvga.py      # lấy DVGA_AUTH_HEADER + dvga_schema.json  -> tokens.env
python3 main_pipeline/run_security_tests.py


# Cách 3 — Chạy hết từ đầu đến cuối, 1 lệnh duy nhất
cd ~/fuzzing-tool
python3 main_pipeline/run_all.py