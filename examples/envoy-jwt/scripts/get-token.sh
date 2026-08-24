#!/usr/bin/env bash
# Mint a Dex id_token (RS256 JWT) for one of the demo users via the OAuth2
# password grant, and print it to stdout. Usage:
#
#   TOKEN=$(examples/envoy-jwt/scripts/get-token.sh alice)
#   curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/get
#
# The password for each demo user is their first name (see dex/config.yaml).
# The script prints only the JWT on stdout; diagnostic output goes to stderr so
# `$(...)` captures just the token.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: get-token.sh <user> [dex-url]
  user     one of: alice | bob | carol | mallory  (password == first name)
  dex-url  defaults to http://localhost:5556
EOF
  exit 2
}

user="${1:-}"
[[ -n "$user" ]] || usage
dex_url="${2:-http://localhost:5556}"

declare -A PASS=(
  [alice]=alice
  [bob]=bob
  [carol]=carol
  [mallory]=mallory
)
declare -A EMAIL=(
  [alice]=alice@bouncer.dev
  [bob]=bob@bouncer.dev
  [carol]=carol@bouncer.dev
  [mallory]=mallory@bouncer.dev
)

pass="${PASS[$user]:-}"
email="${EMAIL[$user]:-}"
if [[ -z "$pass" || -z "$email" ]]; then
  echo "unknown user '$user' (try: alice, bob, carol, mallory)" >&2
  exit 2
fi

resp=$(curl -sS -X POST "${dex_url}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=bouncer-demo" \
  --data-urlencode "username=${email}" \
  --data-urlencode "password=${pass}" \
  --data-urlencode "scope=openid profile email" 2>&1) || {
    echo "token request failed: $resp" >&2
    exit 1
  }

token=$(printf '%s' "$resp" | jq -r '.id_token // empty' 2>/dev/null || true)
if [[ -z "$token" ]]; then
  echo "no id_token in response: $resp" >&2
  exit 1
fi

printf '%s' "$token"
