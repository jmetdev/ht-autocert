#!/usr/bin/env bash
# Install a GitHub Actions runner on this host, labeled `htac`.
# GitHub-hosted jobs cannot SSH here, so deploy runs on this box.
#
#   RUNNER_TOKEN=<registration-token> ./scripts/install-github-runner.sh
#
# Create the token at:
#   GitHub → repo → Settings → Actions → Runners → New self-hosted runner
set -Eeuo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }
[[ -n "${RUNNER_TOKEN:-}" ]] || { echo "ERROR: set RUNNER_TOKEN" >&2; exit 1; }

REPO_URL="${RUNNER_REPO_URL:-https://github.com/jmetdev/ht-autocert}"
APP_DIR="${HTAC_DIR:-/opt/ht-autocert}"
RUNNER_DIR="${RUNNER_DIR:-/opt/actions-runner}"
RUNNER_USER="${RUNNER_USER:-github-runner}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname -s)}"
LABELS="${RUNNER_LABELS:-htac}"

if ! id -u "$RUNNER_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$RUNNER_USER"
fi
usermod -aG docker "$RUNNER_USER"

if [[ -d "$APP_DIR" ]]; then
  chown -R "$RUNNER_USER:$RUNNER_USER" "$APP_DIR"
  [[ -f "$APP_DIR/.env.htac" ]] && chmod 600 "$APP_DIR/.env.htac"
fi

install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
cd "$RUNNER_DIR"

if [[ ! -x ./config.sh ]]; then
  tag="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/\1/p' | head -n1)"
  ver="${tag#v}"
  tarball="actions-runner-linux-x64-${ver}.tar.gz"
  curl -fsSL -o "$tarball" \
    "https://github.com/actions/runner/releases/download/${tag}/${tarball}"
  tar xzf "$tarball"
  rm -f "$tarball"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
fi

sudo -u "$RUNNER_USER" ./config.sh --unattended \
  --url "$REPO_URL" \
  --token "$RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$LABELS" \
  --replace

./svc.sh install "$RUNNER_USER"

svc="$(basename "$(compgen -G /etc/systemd/system/actions.runner.*.service | head -n1)")"
if [[ -n "$svc" ]]; then
  install -d "/etc/systemd/system/${svc}.d"
  printf '[Service]\nSupplementaryGroups=docker\n' > "/etc/systemd/system/${svc}.d/docker.conf"
  systemctl daemon-reload
fi

./svc.sh start
./svc.sh status
printf 'Runner %s installed with labels: %s\n' "$RUNNER_NAME" "$LABELS"
