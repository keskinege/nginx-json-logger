#!/usr/bin/env bash
#
# Mint an HS256 JWT for the jsonlog demo. The demo key is public: it comes from
# deploy/*/jwks.json (key `fantasticjwt`, kid 0001). Pass --secret or JWT_SECRET
# to override.
#
#   ./mint-hs256.sh [--exp-in 3600] [--aud api] [--iss https://dummy-idp.local]
#                   [--sub alice] [--secret <key>]
#
# Requires openssl and jq.
#
set -euo pipefail

EXP_IN=3600
AUD=api
ISS="https://dummy-idp.local"
SUB=alice
SECRET=${JWT_SECRET:-}

while [ $# -gt 0 ]; do
    case "$1" in
        --exp-in) EXP_IN=${2:?}; shift 2 ;;
        --aud)    AUD=${2:?}; shift 2 ;;
        --iss)    ISS=${2:?}; shift 2 ;;
        --sub)    SUB=${2:?}; shift 2 ;;
        --secret) SECRET=${2:?}; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$SECRET" ]; then
    HERE=$(cd "$(dirname "$0")" && pwd)
    for f in /etc/nginx/conf.d/jsonlog/jwks.json "$HERE/jwks.json" "$HERE/../kubernetes/jwks.json"; do
        [ -s "$f" ] || continue
        k=$(jq -r '.keys[0].k // empty' "$f" 2>/dev/null) || continue
        [ -n "$k" ] || continue
        p=$(printf '%s' "$k" | tr '_-' '/+')
        case $(( ${#p} % 4 )) in 2) p="$p==" ;; 3) p="$p=" ;; esac
        SECRET=$(printf '%s' "$p" | openssl base64 -d -A 2>/dev/null) || continue
        [ -n "$SECRET" ] && break
    done
fi
if [ -z "$SECRET" ]; then
    echo "no demo key: pass --secret / set JWT_SECRET, or run from the repo with deploy/*/jwks.json" >&2
    exit 1
fi

command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

now=$(date +%s)
exp=$((now + EXP_IN))

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

header=$(printf '%s' '{"alg":"HS256","typ":"JWT","kid":"0001"}' | b64url)
payload=$(jq -cn \
    --arg iss "$ISS" --arg sub "$SUB" --arg aud "$AUD" \
    --argjson iat "$now" --argjson exp "$exp" \
    '{iss:$iss, sub:$sub, aud:$aud, roles:["devops"], iat:$iat, exp:$exp}' \
    | b64url)

signing_input="$header.$payload"
signature=$(printf '%s' "$signing_input" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)

printf '%s.%s\n' "$signing_input" "$signature"
