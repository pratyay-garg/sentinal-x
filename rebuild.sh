#!/usr/bin/env bash
# Reproducible rebuild of the sentinal-x stack (docker compose project: sentinalx).
#
# The frontend and backend images are BAKED at build time (no live source
# mount), so source changes only take effect after an image rebuild. This script
# always rebuilds from the current working tree, so "some things update, some
# don't" cannot happen.
#
#   ./rebuild.sh            # rebuild images + restart, keep the database
#   ./rebuild.sh --hard     # also wipe THIS project's DB + evidence volumes (clean slate)
#   ./rebuild.sh --no-cache # rebuild images ignoring the build cache
#
# It only ever touches the `sentinalx` compose project, so other Docker projects
# on the machine are never affected. Practice targets are separate: see labs/README.md.
set -euo pipefail
cd "$(dirname "$0")"

PROFILE=()
BUILD_ARGS=()
HARD=0
for arg in "$@"; do
  case "$arg" in
    --hard) HARD=1 ;;
    --no-cache) BUILD_ARGS+=(--no-cache) ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo ">> stopping the sentinalx stack"
docker compose "${PROFILE[@]}" down --remove-orphans

if [[ "$HARD" == "1" ]]; then
  echo ">> wiping sentinalx database + evidence volumes (clean slate)"
  docker volume rm sentinalx_discovery_pgdata sentinalx_discovery_evidence 2>/dev/null || true
fi

echo ">> building images from current source"
docker compose "${PROFILE[@]}" build "${BUILD_ARGS[@]}"

echo ">> starting the stack (api runs 'alembic upgrade head' on boot)"
docker compose "${PROFILE[@]}" up -d

echo ">> status"
docker compose "${PROFILE[@]}" ps
echo ">> done. Console: http://localhost:3001  (hard-refresh the browser: Ctrl+Shift+R)"
