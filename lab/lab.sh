#!/usr/bin/env bash

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$LAB_DIR/docker-compose.yml"
CRAPI_COMPOSE="$LAB_DIR/crapi-compose.yml"
# Compose chính thức của OWASP crAPI. Nếu 404, đổi 'main' -> 'develop'.
CRAPI_URL="https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml"

log() { printf '\n\033[1;36m[lab]\033[0m %s\n' "$*"; }
err() { printf '\n\033[1;31m[lab][X]\033[0m %s\n' "$*" >&2; }

need_docker() {
  command -v docker >/dev/null 2>&1 || { err "Chưa có 'docker'. Cài Docker trước."; exit 1; }
  docker compose version >/dev/null 2>&1 || { err "Thiếu 'docker compose' plugin."; exit 1; }
}

fetch_crapi() {
  if [ ! -f "$CRAPI_COMPOSE" ]; then
    log "Tải compose chính thức của crAPI về $CRAPI_COMPOSE ..."
    curl -fsSL "$CRAPI_URL" -o "$CRAPI_COMPOSE" || {
      err "Không tải được crAPI compose từ $CRAPI_URL (thử đổi main->develop trong lab.sh)."
      return 1
    }
  fi
}

up() {
  need_docker

  log "1/3 Kéo & chạy VAmPI + DVGA ..."
  docker compose -f "$COMPOSE" up -d

  log "Chờ VAmPI sẵn sàng rồi khởi tạo DB (/createdb) ..."
  for _ in $(seq 1 20); do
    if curl -fsS "http://localhost:5002/createdb" >/dev/null 2>&1; then
      log "VAmPI: DB đã khởi tạo."
      break
    fi
    sleep 2
  done

  log "2/3 Chạy crAPI (stack nhiều service, có thể lâu lần đầu) ..."
  if fetch_crapi; then
    docker compose -f "$CRAPI_COMPOSE" -p crapi pull
    docker compose -f "$CRAPI_COMPOSE" -p crapi up -d
  else
    err "Bỏ qua crAPI — chạy tay theo lab/README.md nếu cần."
  fi

  log "3/3 Xong. Kiểm tra: bash lab/lab.sh status"
}

down() {
  need_docker
  log "Dừng VAmPI + DVGA ..."
  docker compose -f "$COMPOSE" down -v || true
  if [ -f "$CRAPI_COMPOSE" ]; then
    log "Dừng crAPI ..."
    docker compose -f "$CRAPI_COMPOSE" -p crapi down -v || true
  fi
  log "Đã dừng toàn bộ."
}

status() {
  need_docker
  log "Container đang chạy:"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
  log "Kiểm tra cổng target:"
  for pair in "VAmPI=http://localhost:5002/createdb" "crAPI=http://localhost:8888/" "DVGA=http://localhost:5013/"; do
    name="${pair%%=*}"; url="${pair#*=}"
    if curl -fsS -o /dev/null --max-time 4 "$url" 2>/dev/null; then
      printf '  [+] %-6s READY  (%s)\n' "$name" "$url"
    else
      printf '  [X] %-6s chưa phản hồi (%s)\n' "$name" "$url"
    fi
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "Dùng: bash lab/lab.sh {up|down|status}"; exit 1 ;;
esac
