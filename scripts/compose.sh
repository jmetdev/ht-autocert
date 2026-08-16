#!/usr/bin/env bash
# Shared docker compose argv builder for ./htac and deployment scripts.
set -euo pipefail

_htac_compose_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

htac_compose() {
  local env_file="${HTAC_ENV_FILE:-.env.htac}"
  local -a cmd=(docker compose)

  if [[ -f "$_htac_compose_dir/$env_file" ]]; then
    cmd+=(--env-file "$env_file")
  fi

  cmd+=(-f docker-compose.yml)

  if [[ -n "${HTAC_COMPOSE_OVERLAY:-}" ]]; then
    local overlay
    for overlay in $HTAC_COMPOSE_OVERLAY; do
      cmd+=(-f "$overlay")
    done
  fi

  (cd "$_htac_compose_dir" && "${cmd[@]}" "$@")
}
