#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ENV_FILE="${HTAC_ENV_FILE:-.env.htac}"
export HTAC_COMPOSE_OVERLAY="docker-compose.vps.yml"

# shellcheck source=scripts/compose.sh
source scripts/compose.sh

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || die "Docker is not installed"
command -v curl >/dev/null || die "curl is not installed"
docker compose version >/dev/null || die "Docker Compose v2 is not installed"
[[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing; copy .env.htac.example and fill it in"

# Read the same simple KEY=value format Docker Compose accepts without sourcing
# secrets as shell code.
value() {
  local key="$1"
  sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n 1 | tr -d '\r'
}

for key in HTAC_MASTER_KEY HTAC_CLOUDFLARE_API_TOKEN HTAC_API_TOKEN HTAC_DOMAIN; do
  [[ -n "$(value "$key")" ]] || die "$key must be set in $ENV_FILE"
done

domain="$(value HTAC_DOMAIN)"
redirect="$(value HTAC_WEBEX_REDIRECT_URI)"
if [[ -n "$redirect" && "$redirect" != "https://${domain}/auth/callback" ]]; then
  die "HTAC_WEBEX_REDIRECT_URI must be https://${domain}/auth/callback"
fi

printf 'Building and starting ht-autocert for %s...\n' "$domain"
htac_compose build --pull htac
htac_compose run --rm --entrypoint htac htac migrate
htac_compose up -d --remove-orphans
htac_compose ps

exec scripts/vps-smoke-test.sh
