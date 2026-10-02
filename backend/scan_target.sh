#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: ./scan_target.sh TARGET_URL [PROFILE]
#   ./scan_target.sh https://authorized.example.com/ fast
#   ./scan_target.sh https://authorized.example.com/ deep
#
# Prefer a target that shares the Compose bridge with the workers, addressed by
# its container name. Remote/internet targets you are authorised to test also
# work directly (the workers have egress). The host-gateway / host-published
# path (host.docker.internal) is unreliable on Docker Desktop + WSL2 and can
# pass Discovery yet fail Validation's preflight with [Errno 101].
TARGET_URL="${1:-}"
PROFILE="${2:-deep}"
[[ -n "$TARGET_URL" ]] || { printf 'Usage: %s TARGET_URL [fast|deep]\n' "$0" >&2; exit 2; }
# Optional exact HTTP headers for an authenticated crawl, as a JSON object.
# Provide via the environment so cookies stay out of shell history, e.g.:
#   AUTH_HEADERS_JSON='{"Authorization":"Bearer <token>"}' \
#     ./scan_target.sh https://authorized.example.com/ deep
# Leave empty for an unauthenticated-only scan. Values are AES-GCM encrypted
# in Postgres and automatically expire; they never appear in scan events.
AUTH_HEADERS_JSON="${AUTH_HEADERS_JSON:-}"
POLL_SECONDS=5
TIMEOUT_SECONDS=1800

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE="${SCRIPT_DIR}/.env"
RUNTIME_ENV=$(mktemp /tmp/discovery-scan-env.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/discovery-scan-response.XXXXXX)
REQUEST_FILE=$(mktemp /tmp/discovery-scan-request.XXXXXX)

cleanup() {
  rm -f -- "$RUNTIME_ENV" "$RESPONSE_FILE" "$REQUEST_FILE"
}
trap cleanup EXIT

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is not installed or not on PATH'
command -v curl >/dev/null 2>&1 || fail 'curl is not installed or not on PATH'
command -v python3 >/dev/null 2>&1 || fail 'python3 is not installed or not on PATH'
docker compose version >/dev/null 2>&1 || fail 'the Docker Compose plugin is unavailable'

[[ -f "$ENV_FILE" ]] || fail "${ENV_FILE} is missing; copy .env.example to .env first"
[[ "$TARGET_URL" =~ ^https?://[^[:space:]]+$ ]] || fail 'TARGET_URL must be a complete http:// or https:// URL'

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

[[ -n "${DISCOVERY_API_KEY:-}" ]] || fail 'DISCOVERY_API_KEY is missing from .env'
[[ "$DISCOVERY_API_KEY" != changeme-* ]] || fail 'replace the placeholder DISCOVERY_API_KEY in .env'

# Keep session cookies out of this tracked script and shell history. Pressing
# Enter retains the normal unauthenticated scan path.
if [[ -z "$AUTH_HEADERS_JSON" ]]; then
  read -r -s -p 'Optional auth headers JSON (Enter for none): ' AUTH_HEADERS_JSON
  printf '\n'
fi

printf '\nTarget:  %s\nProfile: %s\n' "$TARGET_URL" "$PROFILE"
if [[ -n "$AUTH_HEADERS_JSON" ]]; then
  printf 'Auth:    configured (value hidden)\n'
else
  printf 'Auth:    none\n'
fi
printf 'Only scan systems you own or are explicitly authorized to test.\n'
read -r -p 'Type YES to confirm authorization: ' AUTHORIZATION
[[ "$AUTHORIZATION" == 'YES' ]] || fail 'authorization was not confirmed'

# Build a private, short-lived Compose env file. It copies the operator's
# secrets but replaces scope with exactly this target. It is deleted on exit.
awk '!/^(DISCOVERY_ENV_FILE|SCOPE_ALLOWLIST)=/' "$ENV_FILE" >"$RUNTIME_ENV"
printf '\nSCOPE_ALLOWLIST=%s\n' "$TARGET_URL" >>"$RUNTIME_ENV"
if [[ -n "$AUTH_HEADERS_JSON" ]]; then
  python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert isinstance(v,dict) and v; assert all(isinstance(k,str) and isinstance(x,str) for k,x in v.items())' \
    "$AUTH_HEADERS_JSON" || fail 'AUTH_HEADERS_JSON must be a non-empty JSON object of string values'
  if [[ -z "${DISCOVERY_CREDENTIAL_ENCRYPTION_KEY:-}" ]]; then
    DISCOVERY_CREDENTIAL_ENCRYPTION_KEY=$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')
    printf 'DISCOVERY_CREDENTIAL_ENCRYPTION_KEY=%s\n' "$DISCOVERY_CREDENTIAL_ENCRYPTION_KEY" >>"$RUNTIME_ENV"
  fi
fi
chmod 600 "$RUNTIME_ENV"
export DISCOVERY_ENV_FILE="$RUNTIME_ENV"

cd "$SCRIPT_DIR"

printf '\n[1/7] Building and starting Discovery + Validation...\n'
docker compose up -d --build api worker validation-worker

printf '[2/7] Waiting for the API...\n'
api_ready=false
for _ in $(seq 1 60); do
  if curl --silent --fail --max-time 2 http://localhost:8000/health/ready >/dev/null; then
    api_ready=true
    break
  fi
  sleep 2
done
[[ "$api_ready" == true ]] || fail 'Discovery API did not become ready within 120 seconds'

printf '[3/7] Submitting the authorized scan...\n'
python3 - "$TARGET_URL" "$PROFILE" "$AUTH_HEADERS_JSON" >"$REQUEST_FILE" <<'PY'
import json
import sys

payload = {"target": sys.argv[1], "profile": sys.argv[2]}
if sys.argv[3]:
    payload["custom_headers"] = json.loads(sys.argv[3])
json.dump(payload, sys.stdout, separators=(",", ":"))
PY
HTTP_CODE=$(curl --silent --show-error --max-time 30 \
  --output "$RESPONSE_FILE" --write-out '%{http_code}' \
  -X POST http://localhost:8000/api/v1/discovery/scans \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data-binary "@${REQUEST_FILE}")

if [[ "$HTTP_CODE" != '202' ]]; then
  printf 'API response (HTTP %s):\n' "$HTTP_CODE" >&2
  python3 -m json.tool "$RESPONSE_FILE" 2>/dev/null || sed -n '1,20p' "$RESPONSE_FILE"
  fail 'scan submission failed'
fi

JOB_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])' <"$RESPONSE_FILE")
[[ "$JOB_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
  || fail 'API returned an invalid job ID'
printf 'Job ID: %s\n' "$JOB_ID"

printf '[4/7] Waiting for scan completion'
DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
while (( SECONDS < DEADLINE )); do
  HTTP_CODE=$(curl --silent --show-error --max-time 15 \
    --output "$RESPONSE_FILE" --write-out '%{http_code}' \
    -H "X-API-Key: ${DISCOVERY_API_KEY}" \
    "http://localhost:8000/api/v1/discovery/scans/${JOB_ID}")
  [[ "$HTTP_CODE" == '200' ]] || fail "status request returned HTTP ${HTTP_CODE}"

  STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <"$RESPONSE_FILE")
  case "$STATUS" in
    completed)
      printf ' completed.\n'
      break
      ;;
    failed)
      printf ' failed.\n' >&2
      python3 -m json.tool "$RESPONSE_FILE" >&2
      docker compose logs --tail=150 worker >&2
      exit 1
      ;;
    queued|claimed|running)
      printf '.'
      sleep "$POLL_SECONDS"
      ;;
    *)
      fail "unexpected job status: ${STATUS}"
      ;;
  esac
done

[[ "${STATUS:-}" == 'completed' ]] || {
  printf '\n' >&2
  docker compose logs --tail=150 worker >&2
  fail "scan did not complete within ${TIMEOUT_SECONDS} seconds"
}

printf '\n[5/7] Discovery event ledger and queued Validation jobs:\n'
curl --fail-with-body --silent --show-error --max-time 30 \
  --output "$RESPONSE_FILE" \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  "http://localhost:8000/api/v1/discovery/scans/${JOB_ID}/events?after=0"
python3 -m json.tool "$RESPONSE_FILE"

mapfile -t VALIDATION_JOB_IDS < <(python3 - "$RESPONSE_FILE" <<'PY'
import json
import sys

events = json.load(open(sys.argv[1], encoding="utf-8"))
for event in events:
    if event.get("event") == "validation:queued":
        for job_id in event.get("data", {}).get("jobs", []):
            print(job_id)
PY
)

if ((${#VALIDATION_JOB_IDS[@]})); then
  printf 'Waiting for %d Validation job(s)' "${#VALIDATION_JOB_IDS[@]}"
  DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
  while (( SECONDS < DEADLINE )); do
    pending=0
    for VALIDATION_JOB_ID in "${VALIDATION_JOB_IDS[@]}"; do
      curl --fail-with-body --silent --show-error --max-time 30 \
        --output "$RESPONSE_FILE" \
        -H "X-API-Key: ${DISCOVERY_API_KEY}" \
        "http://localhost:8000/api/v1/validation/jobs/${VALIDATION_JOB_ID}"
      VALIDATION_STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <"$RESPONSE_FILE")
      case "$VALIDATION_STATUS" in
        completed) ;;
        failed)
          python3 -m json.tool "$RESPONSE_FILE" >&2
          docker compose logs --tail=150 validation-worker >&2
          fail "Validation job ${VALIDATION_JOB_ID} failed"
          ;;
        queued|claimed|running) pending=$((pending + 1)) ;;
        *) fail "unexpected Validation status: ${VALIDATION_STATUS}" ;;
      esac
    done
    ((pending == 0)) && break
    printf '.'
    sleep "$POLL_SECONDS"
  done
  ((pending == 0)) || fail "Validation did not complete within ${TIMEOUT_SECONDS} seconds"
  printf ' completed.\n'
else
  printf 'No mapped findings were queued for Validation.\n'
fi

printf '\n[6/7] Persisted Discovery + Validation API results:\n'
curl --fail-with-body --silent --show-error --max-time 30 \
  -H "X-API-Key: ${DISCOVERY_API_KEY}" \
  "http://localhost:8000/api/v1/discovery/scans/${JOB_ID}/results" \
  | python3 -m json.tool

for VALIDATION_JOB_ID in "${VALIDATION_JOB_IDS[@]}"; do
  curl --fail-with-body --silent --show-error --max-time 30 \
    -H "X-API-Key: ${DISCOVERY_API_KEY}" \
    "http://localhost:8000/api/v1/validation/jobs/${VALIDATION_JOB_ID}/events?after=0" \
    | python3 -m json.tool
done

printf '\n[7/7] PostgreSQL verification (findings + replayable evidence):\n'
docker compose exec -T db psql -v ON_ERROR_STOP=1 -U discovery -d discovery \
  -c "
SELECT
    f.id,
    f.vuln_class,
    f.template_id,
    f.endpoint,
    f.generated_by,
    f.status,
    f.confidence,
    e.oracle,
    e.expected_status AS evidence_verdict,
    e.generated_by AS evidence_generated_by,
    jsonb_array_length(COALESCE(e.manifest->'transactions', '[]'::jsonb)) AS evidence_transactions,
    COUNT(o.id) AS supporting_observations
FROM findings f
JOIN finding_observations o ON o.finding_id = f.id
LEFT JOIN evidence e ON e.id = f.evidence_id
WHERE o.scan_run_id = (
    SELECT scan_run_id FROM scan_jobs WHERE id = '${JOB_ID}'::uuid
)
GROUP BY f.id, e.id
ORDER BY f.id;
"

printf '\nDone. Recheck results with:\n'
printf 'curl -H "X-API-Key: ${DISCOVERY_API_KEY}" "http://localhost:8000/api/v1/discovery/scans/%s/results"\n' "$JOB_ID"
