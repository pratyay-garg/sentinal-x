#!/usr/bin/env bash
# Bootstrap a DVWA session and print a ready-to-use auth Cookie header.
#
# DVWA gates every vulnerability behind a login and needs its database created
# once. This script does both against the published DVWA (default
# http://localhost:8080), then prints:
#
#     PHPSESSID=<id>; security=low
#
# The PHPSESSID is server-side keyed, so the workers can reuse it when they
# reach the same container as http://dvwa. Feed it to a scan, e.g.:
#
#     AUTH_HEADERS_JSON="{\"Cookie\":\"$(scripts/dvwa_session.sh)\"}" \
#       ./scan_target.sh http://dvwa/ deep
set -Eeuo pipefail

BASE="${1:-http://localhost:8080}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# DVWA renders <input ... name='user_token' value='HEX' />; grab the hex token.
_token() {
  grep -oiE "name=['\"]user_token['\"][^>]*value=['\"][0-9a-f]+" \
    | grep -oiE "[0-9a-f]{16,}" | head -1
}

t="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/setup.php" | _token)"
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null \
  --data-urlencode "create_db=Create / Reset Database" \
  --data-urlencode "user_token=${t}" "$BASE/setup.php"

t="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/login.php" | _token)"
curl -fsS -L -c "$JAR" -b "$JAR" -o /dev/null \
  --data "username=admin&password=password&Login=Login" \
  --data-urlencode "user_token=${t}" "$BASE/login.php"

t="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/security.php" | _token)"
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null \
  --data "security=low&seclev_submit=Submit" \
  --data-urlencode "user_token=${t}" "$BASE/security.php"

sid="$(awk '/PHPSESSID/{v=$7} END{print v}' "$JAR")"
[ -n "$sid" ] || { echo "failed to obtain PHPSESSID from $BASE" >&2; exit 1; }
printf 'PHPSESSID=%s; security=low\n' "$sid"
