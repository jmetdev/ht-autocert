#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=scripts/compose.sh
source scripts/compose.sh

htac_compose --profile test run --rm test
