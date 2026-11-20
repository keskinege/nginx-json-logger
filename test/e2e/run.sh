#!/usr/bin/env bash
set -euo pipefail
BASE=${BASE:-http://localhost:8088}

code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/get?x=1")
[ "$code" = "200" ] || { echo "expected 200, got $code"; exit 1; }

line=$(tail -n 1 logs/json.log)
echo "$line" | jq -e '.schema_version == "1.0.0"' >/dev/null
echo "$line" | jq -e '.event == "http_request"' >/dev/null

curl -sS -H 'X-Request-ID: e2e-rid-1' -H 'Via: 1.1 alpha' -H 'Via: 1.1 beta' \
     -H 'Cookie: session=secret' "$BASE/api/get" >/dev/null
line=$(tail -n 1 logs/json.log)
echo "$line" | jq -e '.request_id == "e2e-rid-1"' >/dev/null
echo "$line" | jq -e '.request.headers.via == ["1.1 alpha","1.1 beta"]' >/dev/null
echo "$line" | jq -e '.request.headers.cookie == "[REDACTED]"' >/dev/null
echo "$line" | jq -e '.request.headers.authorization == null' >/dev/null
echo "$line" | jq -e '.client.remote_addr != null and .timings.request_s >= 0' >/dev/null
curl -sS -X POST -H 'Content-Type: application/json' \
     -d '{"items":[1,2],"password":"hunter2"}' "$BASE/api/post" >/dev/null
tail -n 1 logs/json.log | jq -e '.request.body.json.password == "[REDACTED]"' >/dev/null

python3 - <<'PY' > /tmp/big.json
import json; print(json.dumps({"k": "x" * 40000}))
PY
curl -sS -X POST -H 'Content-Type: application/json' --data-binary @/tmp/big.json "$BASE/api/post" >/dev/null
tail -n 1 logs/json.log | jq -e '.request.body.state == "omitted_too_large"' >/dev/null

curl -sS "$BASE/api/json" >/dev/null
tail -n 1 logs/json.log | jq -e '.response.body.state == "captured" and .response.body.encoding == "utf8"' >/dev/null

curl -sS "$BASE/api/image/png" >/dev/null
tail -n 1 logs/json.log | jq -e '.response.body.encoding == "base64"' >/dev/null

curl -sS --max-time 2 "$BASE/stream/5" >/dev/null || true
tail -n 1 logs/json.log | jq -e '.response.body.state == "not_supported"' >/dev/null

TOKEN=$(node test/e2e/mint-jwt.mjs)

curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/get" | grep -q 200
tail -n 1 logs/json.log | jq -e '.auth.verdict == "not_checked" and .auth.required == false' >/dev/null
tail -n 1 logs/json.log | jq -e '.auth.jwt.claims.sub == "alice" and .auth.jwt.derived.roles == ["ops"]' >/dev/null
tail -n 1 logs/json.log | jq -e '.auth.jwt.checks.signature_valid == null' >/dev/null

curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/get" | grep -q 200
tail -n 1 logs/json.log | jq -e '.auth.verdict == "missing"' >/dev/null

! grep -q "$TOKEN" logs/json.log

curl -sS "$BASE/api/get" >/dev/null
tail -n 1 logs/json.log | jq -e '.upstream.request.url_confidence == "derived"' >/dev/null

curl -sS "$BASE/api/override/get" >/dev/null
tail -n 1 logs/json.log | jq -e '.upstream.request.url_confidence == "overridden" and .upstream.request.url == "https://orders.internal:8443/v1/orders"' >/dev/null

curl -sS "$BASE/api/mapped/get" >/dev/null
tail -n 1 logs/json.log | jq -e '.upstream.request.url_confidence == "partial" and .upstream.request.url == null' >/dev/null

curl -sS "$BASE/api/get" >/dev/null
tail -n 1 logs/json.log | jq -e '.upstream.peer | test(":8080")' >/dev/null

curl -sS "http://localhost:8088/api/syslog/get" >/dev/null
sleep 1
docker compose -f test/e2e/docker-compose.yml logs --no-log-prefix udp-listener \
  | grep '{' | tail -n 1 | sed 's/^<[0-9]*>[^{]*//' \
  | jq -e '.log.transport == "syslog"' >/dev/null

echo "e2e smoke OK"
