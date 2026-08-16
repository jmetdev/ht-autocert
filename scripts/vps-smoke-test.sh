#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ENV_FILE="${HTAC_ENV_FILE:-.env.htac}"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f docker-compose.htac.yml -f docker-compose.vps.yml)
domain="$(sed -n 's/^HTAC_DOMAIN=//p' "$ENV_FILE" | tail -n 1 | tr -d '\r')"
[[ -n "$domain" ]] || { echo "ERROR: HTAC_DOMAIN is not set" >&2; exit 1; }

printf 'Waiting for the application health check...\n'
for _ in $(seq 1 30); do
  id="$("${COMPOSE[@]}" ps -q htac)"
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)"
  [[ "$status" == healthy ]] && break
  sleep 2
done
[[ "${status:-}" == healthy ]] || {
  "${COMPOSE[@]}" logs --tail=100 htac >&2
  echo "ERROR: application did not become healthy" >&2
  exit 1
}

curl --fail --silent --show-error --retry 12 --retry-delay 5 \
  "https://${domain}/healthz" | grep -q '"status":"ok"'
curl --fail --silent --show-error "https://${domain}/auth/config" | grep -q 'webex_enabled'
"${COMPOSE[@]}" run --rm --entrypoint htac htac doctor

printf 'OK: https://%s is healthy; auth configuration and application diagnostics passed.\n' "$domain"
