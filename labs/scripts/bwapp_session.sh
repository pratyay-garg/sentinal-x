#!/usr/bin/env bash
# Bootstrap a bWAPP session and print a ready-to-use auth Cookie header.
#
# bWAPP gates every bug behind a login (bee/bug) and needs its database
# installed once. This script does both against the published bWAPP (default
# http://localhost:8090), then prints:
#
#     PHPSESSID=<id>; security_level=0
#
# The PHPSESSID is server-side keyed, so the workers can reuse it when they
# reach the same container as http://bwapp. security_level=0 selects the "low"
# bugs. Feed it to a scan, e.g.:
#
#     AUTH_HEADERS_JSON="{\"Cookie\":\"$(scripts/bwapp_session.sh)\"}" \
#       ./scan_target.sh http://bwapp/ deep
set -Eeuo pipefail

BASE="${1:-http://localhost:8090}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# One-time database install (idempotent: re-running just re-creates the tables).
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null "$BASE/install.php?install=yes"

# bWAPP's login form has no CSRF token; security_level=0 == "low".
curl -fsS -L -c "$JAR" -b "$JAR" -o /dev/null \
  --data "login=bee&password=bug&security_level=0&form=submit" "$BASE/login.php"

sid="$(awk '/PHPSESSID/{v=$7} END{print v}' "$JAR")"
[ -n "$sid" ] || { echo "failed to obtain PHPSESSID from $BASE" >&2; exit 1; }
printf 'PHPSESSID=%s; security_level=0\n' "$sid"
