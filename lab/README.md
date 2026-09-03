# Lab target — VAmPI · crAPI · DVGA

Ba ứng dụng **cố ý có lỗ hổng**, chạy cục bộ bằng Docker, chỉ dùng cho nghiên cứu/kiểm thử nội bộ.
Port ở đây **cố định** cho khớp các script trong `Schemathesis/`: **VAmPI 5002 · crAPI 8888 · DVGA 5013**.

## Cách nhanh nhất (Linux/macOS) — 1 lệnh

```bash
bash lab/lab.sh up        # kéo image + chạy cả 3 + khởi tạo DB VAmPI
bash lab/lab.sh status    # kiểm tra 3 target đã READY chưa
bash lab/lab.sh down      # dừng + xoá sạch
```

Yêu cầu: `docker` + `docker compose` plugin. crAPI ngốn ~4GB RAM, lần đầu kéo image khá lâu.

```bash
# Cài Docker trên Ubuntu/Debian:
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"   # để chạy docker không cần sudo (đăng xuất/vào lại)
```

---

## Chi tiết từng target (nếu muốn chạy tay)

### VAmPI (REST, cổng 5002)
Image đơn `erev0s/vampi`, đã nằm trong `lab/docker-compose.yml`.
```bash
docker compose -f lab/docker-compose.yml up -d vampi
curl http://localhost:5002/createdb          # BẮT BUỘC 1 lần: khởi tạo dữ liệu
# kiểm tra: curl http://localhost:5002/
```
`vulnerable=1` (mặc định) = bật chế độ có lỗ hổng.

### DVGA (GraphQL, cổng 5013)
Image đơn `dolevf/dvga`, cũng trong `lab/docker-compose.yml`.
```bash
docker compose -f lab/docker-compose.yml up -d dvga
# kiểm tra: mở http://localhost:5013/  (GraphiQL ở /graphiql)
```

### crAPI (REST, cổng 8888) — stack nhiều microservice
crAPI **không có image gộp**, phải dùng compose chính thức của OWASP. `lab.sh up` tự tải về
`lab/crapi-compose.yml`. Chạy tay:
```bash
curl -fsSL https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml \
  -o lab/crapi-compose.yml
docker compose -f lab/crapi-compose.yml -p crapi pull
docker compose -f lab/crapi-compose.yml -p crapi up -d
# Web UI: http://localhost:8888/
```
Nếu URL trên báo 404, đổi nhánh `main` → `develop`.

---

## Sau khi lab chạy — quy trình đầy đủ B → C → tổng hợp

```bash
# 0. (một lần) tạo lại .env chứa Gemini key — .env KHÔNG theo git
echo 'GEMINI_API_KEY=<key-cua-ban>' > .env
pip install -r Schemathesis/requirements.txt      # schemathesis, httpx, pydantic, pyyaml, requests
# cài nuclei binary: https://github.com/projectdiscovery/nuclei/releases (đưa vào PATH)

# 1. B — sinh 4 file payload đúng định dạng (qua Gemini)
python scripts/gen_payloads.py

# 2. Lấy token auth từ target đang chạy
python Schemathesis/run_auth.py     # -> tokens.env (VAmPI + crAPI)
python Schemathesis/run_dvga.py     # -> tokens.env (DVGA) + dvga_schema.json

# 3. C — chạy fuzzing
python Schemathesis/run_security_tests.py                              # schemathesis: vampi + crapi + dvga
python -m executor.run_nuclei --input benchmark/suite.json \
       --export-dir ../../results/nuclei                               # nuclei (chạy trong Nuclei/executor/)

# 4. Tổng hợp nuclei + schemathesis -> 1 báo cáo cho máy + người
python scripts/aggregate_results.py
#   -> results/findings_summary.csv   (người)
#   -> results/findings_summary.ndjson (máy)
```
