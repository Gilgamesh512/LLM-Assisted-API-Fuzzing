# Module C — Nuclei Test Executor

Nhận JSON test suite (từ module B), sinh template Nuclei tạm, gọi Nuclei bắn vào
mục tiêu, parse & chuẩn hóa kết quả trả về pipeline.

## Cài đặt
```bash
pip install -r requirements.txt
# Cài Nuclei: https://github.com/projectdiscovery/nuclei/releases
# (Windows bị Windows Defender chặn -> nên chạy trong WSL/Linux)
nuclei -version
```

## Chạy
```bash
# suite do module B sinh ra:
python -m executor.run_nuclei --input suite_tu_B.json

# ghi đè target / xuất JSON cho pipeline:
python -m executor.run_nuclei --input suite.json --target http://host --output ket_qua.json --json

# xuất 2 file kết quả: vulnerabilities.csv (người) + vulnerabilities.ndjson (máy):
python -m executor.run_nuclei --input suite.json --export-dir ket_qua
```
Nếu nuclei không nằm trên PATH: đặt biến `NUCLEI_BIN=/duong/dan/nuclei`.

## Hợp đồng dữ liệu
- Input (từ B): `target` + danh sách `test_cases` (id, endpoint, method, vuln_type,
  path_params, query_params, body, matchers, severity). Xem `schemas.py`.
- Output: `target` + `summary` + `findings` (đã chuẩn hóa). Xem mục 5.3 CLAUDE.md.

## Cấu trúc
- `run_nuclei.py`   — entrypoint + CLI + báo cáo dễ đọc
- `schemas.py`      — pydantic model in/out (validate JSON của B)
- `template_builder.py` — sinh YAML template Nuclei từ test case
- `nuclei_runner.py`    — wrapper subprocess gọi Nuclei
- `tools/suite_from_openapi.py` — sinh suite tự động từ OpenAPI (thay tạm B)
