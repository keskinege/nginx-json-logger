#!/usr/bin/env bash
#
# Install jsonlog into an existing NGINX Plus installation.
# Does not modify nginx.conf: it installs the module + snippets and prints the
# two lines you must add.
#
#   sudo ./install.sh [--prefix /etc/nginx] [--demo] [--test] [--js-only]
#
#   --demo    also install a self-contained test server on :8080 with native
#             auth_jwt and the demo HS256 key in deploy/vm/jwks.json
#   --test    run `nginx -t` at the end
#   --js-only logging module + snippets only; no demo, no JWKS, no auth_jwt
#             directives. Use when JWT validation is already configured.
#             Alias: --no-jwt
#
set -euo pipefail

PREFIX=/etc/nginx
DEMO=0
TEST=0
JS_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=${2:?}; shift 2 ;;
        --demo)   DEMO=1; shift ;;
        --test)   TEST=1; shift ;;
        --js-only|--no-jwt) JS_ONLY=1; shift ;;
        -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$JS_ONLY" = "1" ] && [ "$DEMO" = "1" ]; then
    echo "--js-only and --demo are mutually exclusive" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (use sudo)" >&2
    exit 1
fi

SRC=$(cd "$(dirname "$0")/../.." && pwd)
JSONLOG_DIR="$PREFIX/conf.d/jsonlog"
NJS_DIR="$PREFIX/njs"

echo "==> checking NGINX Plus and njs"
if ! nginx -v 2>&1 | grep -q "nginx-plus"; then
    echo "ERROR: this is not NGINX Plus (nginx -v did not contain 'nginx-plus')." >&2
    echo "       js_access and auth_jwt require Plus." >&2
    exit 1
fi
if [ "$JS_ONLY" = "0" ] && ! nginx -V 2>&1 | grep -q "http_auth_jwt_module"; then
    echo "WARN: auth_jwt not reported by nginx -V; the demo's auth_jwt block will fail nginx -t." >&2
fi
if ! ls "$PREFIX"/modules-enabled/*js* >/dev/null 2>&1 \
   && ! nginx -V 2>&1 | grep -qi "njs"; then
    echo "WARN: njs module not detected. Install nginx-plus-module-njs and add"
    echo "      load_module modules/ngx_http_js_module.so;  to the main context."
fi

echo "==> installing files"
install -d -m 0755 "$NJS_DIR" "$JSONLOG_DIR"
install -m 0644 "$SRC/njs/jsonlog.js" "$NJS_DIR/jsonlog.js"
for f in http location no-body syslog; do
    install -m 0644 "$SRC/conf/jsonlog/$f.conf" "$JSONLOG_DIR/$f.conf"
done

echo "==> ensuring log directory"
if [ ! -d /var/log/nginx ]; then
    install -d -m 0750 -o nginx -g adm /var/log/nginx
fi

echo "==> installing logrotate"
cat > /etc/logrotate.d/nginx-jsonlog <<'ROTATE'
/var/log/nginx/json.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
ROTATE
chmod 0644 /etc/logrotate.d/nginx-jsonlog

if [ "$DEMO" = "1" ]; then
    if ! grep -q "conf.d/jsonlog/http.conf" "$PREFIX/nginx.conf"; then
        echo "ERROR: --demo needs http.conf included first, otherwise nginx -t will fail" >&2
        echo "       because the demo references jsonlog.request before js_import runs." >&2
        echo "" >&2
        echo "  1. add inside http {} in $PREFIX/nginx.conf, BEFORE the conf.d glob:" >&2
        echo "         include $JSONLOG_DIR/http.conf;" >&2
        echo "  2. nginx -t && nginx -s reload" >&2
        echo "  3. re-run: sudo ./install.sh --demo" >&2
        exit 1
    fi
    echo "==> installing demo server on :8080"
    install -m 0644 "$SRC/deploy/vm/jwks.json" "$JSONLOG_DIR/jwks.json"
    install -m 0644 "$SRC/deploy/vm/jsonlog-demo.conf" "$PREFIX/conf.d/jsonlog-demo.conf"
fi

cat <<EOF

==> installed

  $NJS_DIR/jsonlog.js
  $JSONLOG_DIR/{http,location,no-body,syslog}.conf

Required, once, inside http {} in $PREFIX/nginx.conf, BEFORE the conf.d glob:

    include $JSONLOG_DIR/http.conf;

Per logged location:

    include $JSONLOG_DIR/location.conf;     # full capture
    include $JSONLOG_DIR/no-body.conf;      # streaming / SSE

For streaming only? Use no-body.conf instead of location.conf.
Then validate and reload:

    nginx -t && nginx -s reload

EOF

if [ "$DEMO" = "1" ]; then
    cat <<EOF
Demo server is auto-included by the usual conf.d/*.conf glob:

    curl -s localhost:8080/healthz
    TOKEN=\$(./mint-hs256.sh)
    curl -s -H "Authorization: Bearer \$TOKEN" localhost:8080/api/get
    tail -1 /var/log/nginx/json.log | jq .

EOF
fi

if [ "$JS_ONLY" = "1" ]; then
    cat <<EOF

==> logging only

  No auth_jwt directives, no JWKS and no demo server were installed.
  Your existing JWT configuration is untouched: add the capture snippet to the
  locations that already validate tokens.

  Optional, per protected location, to have iss/aud mismatches reported:

      set \$jl_expected_issuer   "https://idp.example.com/realms/prod";
      set \$jl_expected_audience "api";
      set \$jl_allowed_algs      "RS256";

EOF
fi

if [ "$TEST" = "1" ]; then
    echo "==> nginx -t"
    nginx -t
fi
