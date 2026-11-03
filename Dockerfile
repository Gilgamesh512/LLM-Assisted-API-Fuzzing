# Dockerfile — Single-Command All-in-One Container for LLM-Assisted API Fuzzing
FROM python:3.11-slim

LABEL maintainer="Enterprise DevSecOps Team"
LABEL description="All-in-One Container for LLM-Assisted API Fuzzing & Security Testing"

# Thiết lập môi trường
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Cài đặt các gói hệ thống cần thiết và tải Nuclei binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Tải Nuclei CLI (ProjectDiscovery)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip -o nuclei.zip \
    && apt-get update && apt-get install -y unzip && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip && apt-get remove -y unzip && rm -rf /var/lib/apt/lists/*

# Cài đặt Python dependencies
COPY requirements.txt .
COPY Schemathesis/requirements.txt ./Schemathesis-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r Schemathesis-requirements.txt

# Sao chép mã nguồn ứng dụng
COPY . .

# Điểm nhập mặc định là CLI duy nhất
ENTRYPOINT ["python", "fuzzer.py"]
CMD ["scan", "--help"]
