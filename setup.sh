#!/usr/bin/env bash
# =============================================================================
# SENTINAL X - one-time environment bootstrap.
#
# Generates backend/.env from backend/.env.example with fresh random secrets, so
# the stack can be brought up with a single `docker compose up -d`. Scope starts
# empty (fail-closed) — add authorised targets to SCOPE_ALLOWLIST yourself. Safe
# to re-run: it will not overwrite an existing .env unless you pass --force.
#
# Only host dependency: bash + (python3 OR openssl) for random secrets. Docker
# runs everything else.
# =============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="$SCRIPT_DIR/backend"
ENV_FILE="$ENV_DIR/.env"
EXAMPLE="$ENV_DIR/.env.example"

[ -f "$EXAMPLE" ] || { echo "ERROR: $EXAMPLE not found - run this from the repository root." >&2; exit 1; }

if [ -f "$ENV_FILE" ] && [ "${1:-}" != "--force" ]; then
  echo "$ENV_FILE already exists - leaving it untouched."
  echo "Pass --force to regenerate its secrets (this changes the console password)."
  exit 0
fi

# --- portable secret generators: prefer python3, fall back to openssl ---------
have() { command -v "$1" >/dev/null 2>&1; }

gen_token() {  # url-safe random token (letters/digits/-/_)
  if have python3; then python3 -c "import secrets;print(secrets.token_urlsafe(32))"
  elif have openssl; then openssl rand -base64 36 | tr '+/' '-_' | tr -d '=\n'
  else echo "ERROR: need python3 or openssl to generate secrets." >&2; exit 1; fi
}
gen_key32() {  # url-safe base64 of exactly 32 bytes (AES-256-GCM key, keeps padding)
  if have python3; then python3 -c "import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
  elif have openssl; then openssl rand 32 | openssl base64 -A | tr '+/' '-_'
  else echo "ERROR: need python3 or openssl to generate secrets." >&2; exit 1; fi
}

API_KEY="$(gen_token)"
ADMIN_KEY="$(gen_token)"
ENC_KEY="$(gen_key32)"
CONSOLE_PW="$(gen_token)"
SESSION_SECRET="$(gen_token)$(gen_token)"   # >= 32 bytes of entropy

cp "$EXAMPLE" "$ENV_FILE"

# awk-based line replacement (values may contain '=', '-', '_'; safe with FS='=')
set_kv() {
  awk -v k="$1" -v v="$2" 'BEGIN{FS="="} $1==k{print k"="v; next}{print}' "$ENV_FILE" > "$ENV_FILE.tmp" \
    && mv "$ENV_FILE.tmp" "$ENV_FILE"
}

set_kv DISCOVERY_API_KEY                    "$API_KEY"
set_kv DISCOVERY_ADMIN_API_KEY              "$ADMIN_KEY"
set_kv DISCOVERY_CREDENTIAL_ENCRYPTION_KEY  "$ENC_KEY"
set_kv CONSOLE_PASSWORD                     "$CONSOLE_PW"
set_kv CONSOLE_SESSION_SECRET               "$SESSION_SECRET"
set_kv SCOPE_ALLOWLIST                      ""   # fail-closed; add your authorised targets
chmod 600 "$ENV_FILE" 2>/dev/null || true

cat <<EOF

  Generated $ENV_FILE with fresh secrets.

  Operator console login password:
      $CONSOLE_PW

  (Saved in backend/.env as CONSOLE_PASSWORD. Keep that file private.)

  Next:
      docker compose up -d
      open http://localhost:3001   and log in with the password above

  (Optional practice targets live in labs/ — see labs/README.md.)

EOF
