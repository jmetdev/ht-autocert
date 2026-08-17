#!/usr/bin/env bash
# Pull the image GitHub Actions published to GHCR and restart the console.
# Does not use the Caddy VPS overlay -- Nginx Proxy Manager already owns 80/443.
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ENV_FILE="${HTAC_ENV_FILE:-.env.htac}"
IMAGE="${HTAC_IMAGE:-ghcr.io/jmetdev/ht-autocert:latest}"
export HTAC_IMAGE="$IMAGE"

# shellcheck source=scripts/compose.sh
source scripts/compose.sh

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || die "Docker is not installed"
command -v curl >/dev/null || die "curl is not installed"
docker compose version >/dev/null || die "Docker Compose v2 is not installed"
[[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing"

if [[ -n "${GHCR_TOKEN:-}" ]]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io \
    -u "${GHCR_USER:-github}" --password-stdin >/dev/null
fi

printf 'Deploying %s\n' "$IMAGE"
htac_compose pull htac
htac_compose run --rm --no-deps --no-build --entrypoint htac htac migrate
htac_compose up -d --no-build --pull never --remove-orphans
htac_compose ps

bind="$(sed -n 's/^HTAC_BIND=//p' "$ENV_FILE" | tail -n 1 | tr -d '\r')"
port="$(sed -n 's/^HTAC_HOST_PORT=//p' "$ENV_FILE" | tail -n 1 | tr -d '\r')"
bind="${bind:-127.0.0.1}"
port="${port:-8866}"

ok=0
for _ in $(seq 1 30); do
  if curl -fsS "http://${bind}:${port}/healthz" >/dev/null; then
    ok=1
    break
  fi
  sleep 2
done
[[ "$ok" -eq 1 ]] || die "http://${bind}:${port}/healthz did not become ready"

printf 'Healthy at http://%s:%s/healthz\n' "$bind" "$port"
