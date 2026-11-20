# jsonlog

Full request/response JSON access logging for **NGINX Plus**. One njs file plus
nginx snippets. JWT payloads are **decoded and logged, never verified** — this is
an observability component, not an authorization one.

Install on a VM: `deploy/vm/README.md`. Kubernetes test deployment:
`deploy/kubernetes/README.md`.

## What gets logged

`ts`, `request_id`, `nginx`, `client`, `tls`, `server`, `request` (method, URI,
args, headers, body), `auth` (JWT header, all claims, derived roles/scopes,
local `exp`/`nbf`/`iat` checks), `response` (status, headers, body), `upstream`
(peer, configured target, derived URL + confidence), `timings`, and `log`
(transport, redactions, internal errors).

The raw bearer token is never written — only a SHA-256 fingerprint, its length,
the claims and the decode verdict. Signatures are not checked and no request is
rejected.

---

## Files on the VM

| Path | Purpose |
|---|---|
| `/etc/nginx/njs/jsonlog.js` | the whole module |
| `/etc/nginx/conf.d/jsonlog/http.conf` | `js_import`, variables, `log_format`, `access_log` |
| `/etc/nginx/conf.d/jsonlog/location.conf` | full capture: headers, request body, response body |
| `/etc/nginx/conf.d/jsonlog/no-body.conf` | headers only — SSE, large downloads |
| `/etc/nginx/conf.d/jsonlog/syslog.conf` | UDP transport override |

---

## Enable it on an existing VM

### 1. Once, in `http {}`

```nginx
load_module modules/ngx_http_js_module.so;   # main context; skip if modules-enabled/ loads it

http {
    include /etc/nginx/conf.d/jsonlog/http.conf;
}
```

This defines `log_format jsonlog escape=none` and an `access_log` at `http`
scope, so every request logs. Locations without a capture snippet still produce
a record with `body.state: "not_read"`.

### 2. Per location

```nginx
# full capture (request + response bodies)
location /api/ {
    include /etc/nginx/conf.d/jsonlog/location.conf;
    proxy_pass http://backend;
}

# streaming: headers only, no body buffering
location /events/ {
    include /etc/nginx/conf.d/jsonlog/no-body.conf;
    proxy_pass http://backend;
}

# opt a location or server out entirely
location /healthz/ {
    access_log off;
    proxy_pass http://backend;
}
```

No other directive is required. There is no `auth_jwt`, no JWKS endpoint and no
`/_jwks` location.

### 3. Reload

```sh
sudo nginx -t && sudo nginx -s reload
```

---

## Configuration

### Per-location hints (`set`, no module edit)

```nginx
set $jl_upstream_scheme      "https";   # nginx does not expose the proxy scheme
set $jl_upstream_url         "https://orders.internal:8443/v1/orders";  # exact URL
set $jl_upstream_host_header "orders.internal";  # if proxy_set_header Host differs
set $jl_upstream_uri_mapped  "1";       # proxy_pass has a URI part → url:null, partial
```

`url_confidence` is `overridden`, `derived` or `partial`; `partial` means the
record deliberately carries no URL rather than a plausible wrong one.

### Module constants (edit `njs/jsonlog.js`, then reload)

| Constant | Default | Meaning |
|---|---|---|
| `TRANSPORT_LIMITS` | file 32768 / syslog 2048 | body caps per transport |
| `SYSLOG_RECORD_BUDGET` | `8192` | datagram budget (256 B reserved for the prefix) |
| `CLOCK_SKEW_S` | `30` | tolerance for the local `exp`/`nbf`/`iat` observations |

### Transport

```nginx
# default: file
access_log /var/log/nginx/json.log jsonlog buffer=64k flush=1s;

# UDP: server/location level, replaces the inherited file access_log
set $jl_transport syslog;
include /etc/nginx/conf.d/jsonlog/syslog.conf;
```

Syslog is UDP-only, lossy, one datagram per record, with an RFC3164/5424 prefix
before the JSON. Bodies are limited to 2 KiB and the record to ~8 KiB.

### Kill switch

```nginx
set $jl_bodies 0;   # server or location; disables body capture only
```

Metadata, headers and JWT claims still log. Requires `nginx -s reload`.

---

## Reading the log

```sh
# one request, pretty
sudo tail -1 /var/log/nginx/json.log | jq .

# internal logger errors (should be empty)
jq -c 'select(.log.errors | length > 0)' /var/log/nginx/json.log

# requests carrying an expired token (local observation, not enforcement)
jq -c 'select(.auth.jwt.checks.exp_ok == false)' /var/log/nginx/json.log

# slow requests
jq -c 'select(.timings.request_s > 1) | {request_id, uri: .request.uri, s: .timings.request_s}' /var/log/nginx/json.log

# status distribution
jq -r '.response.status' /var/log/nginx/json.log | sort | uniq -c | sort -rn

# tokens expiring within 5 minutes
jq -c 'select(.auth.jwt.derived.expires_in_s != null and .auth.jwt.derived.expires_in_s < 300) | {sub: .auth.jwt.claims.sub, left: .auth.jwt.derived.expires_in_s}' /var/log/nginx/json.log

# roles seen per subject
jq -r 'select(.auth.jwt != null) | [.auth.jwt.claims.sub, (.auth.jwt.derived.roles | join(","))] | @tsv' /var/log/nginx/json.log | sort -u

# what was redacted
jq -c '.log.redactions' /var/log/nginx/json.log | sort -u
```

### Field values that explain themselves

| Field | Values |
|---|---|
| `request.body.state` / `response.body.state` | `captured`, `empty`, `omitted`, `omitted_too_large`, `omitted_transport_limit`, `chunked`, `not_read`, `not_supported`, `error` |
| `auth.verdict` | `missing` (no bearer), `malformed` (undecodable), `not_checked` (decoded, never verified) |
| `auth.validation.errors[].code` | see the validation table below |
| `auth.validation.reason_hint` | `signature_or_key` when a denial has no observable cause, else `null` |
| `auth.required` | always `false` — nothing is enforced |
| `auth.jwt.checks.signature_valid` | always `null` |
| `auth.jwt.checks.exp_ok` / `nbf_ok` / `iat_ok` | local observation from claims and a 30 s skew |
| `upstream.request.url_confidence` | `derived`, `overridden`, `partial` |
| `log.transport` | `file`, `syslog` |

---

## Logging JWT validation failures (`auth_jwt`)

If a location uses native `auth_jwt`, the record explains the 401 without this
module performing verification:

- `emit` decodes the token **at log phase** even when `auth_jwt` denied before
  `js_access` ran, so claims are still present.
- `auth.validation.errors[]` lists observable defects:

  | Code | Meaning |
  |---|---|
  | `token_missing` | 401 + `WWW-Authenticate: Bearer`, no token |
  | `malformed_token` | not three base64url segments of JSON |
  | `expired` / `not_yet_valid` / `iat_in_future` | claim vs `ts` with 30 s skew |
  | `alg_not_allowed` | `alg` outside `$jl_allowed_algs` |
  | `issuer_mismatch` / `audience_mismatch` | claim vs configured expectation |
  | `no_subject` | `sub` absent |

- `auth.validation.signature` is always `unverified`. When the status is 401/403
  and **no** observable defect exists, `reason_hint` is `signature_or_key` with a
  note: the signature, key selection (`kid`) or an unstated policy caused it and
  cannot be confirmed here.
- Expectations are optional `set` variables; unset means "skip comparison":

```nginx
set $jl_expected_issuer   "https://idp.example.com/realms/prod";
set $jl_expected_audience "api";
set $jl_allowed_algs      "RS256";
```

```sh
# every denial that has a nameable cause
jq -c 'select(.auth.validation.errors | length > 0)
       | {request_id, v: .auth.verdict, e: .auth.validation.errors}' /var/log/nginx/json.log

# denials with no observable cause (signature/key/policy)
jq -c 'select(.auth.validation.reason_hint != null) | {request_id, hint: .auth.validation.reason_hint}' /var/log/nginx/json.log
```

Caveats: request bodies may be absent on a denied request because `js_access`
can be skipped when `auth_jwt` denies first; and a signature failure is a
hypothesis, never a verified verdict. Set the expectations to the same values
the gateway enforces, or you will log mismatches that are real but irrelevant
to the 401.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Record is `{"event":"log_error"}` | `emit` threw twice. Check `error_log` for `emit_failed`; usually an unexpected header/claim shape. |
| `log.errors` non-empty | Read the entry's `component` (`request`, `request_body`, `response_body`, `emit`). |
| `auth.verdict: "missing"` | No `Authorization: Bearer` header on that request. |
| `auth.verdict: "malformed"` | Token was not three base64url segments of JSON. |
| `auth.verdict: "not_checked"` | Normal: the token was decoded, not verified. |
| `upstream` is `null` | Response came from `js_content`/static/`return`, not a proxied upstream. |
| `url_confidence: "partial"` | `proxy_pass` has a URI part or uses variables. Set `$jl_upstream_url` for an exact value. |
| Bodies missing | Check `body.state`: oversize, chunked (no `Content-Length`), or the location used `no-body.conf`. |
| Empty body but upstream sent one | Probe P2: `js_body_filter` interaction with `proxy_buffering`. See the ops doc. |
| Log grows too fast | Lower caps in `TRANSPORT_LIMITS`, disable bodies with `$jl_bodies 0`, or rotate sooner. |

### Caveats

- **`location.conf` sets `proxy_set_header X-Request-ID`.** A `proxy_set_header`
  at location level disables inheritance of every parent-level
  `proxy_set_header`, so `Host`/`X-Forwarded-For` defined in `server {}` will not
  be forwarded. Duplicate them in the location or drop that line.
- **`escape=none` is mandatory.** Changing the `log_format` escape corrupts every
  record.
- **The log contains PII.** Identity claims and request bodies; keep `0640`,
  bound retention, and treat it as a personal-data store.
- **OSS nginx is not supported** (`js_access` requires the njs module and njs ≥ 0.9.9).
- **Probes P2–P8 are pending** in this repo's environment (no Plus licence):
  `js_body_filter` buffering, njs version, upstream variables, encoding, datagram
  limits. See the ops doc; run them on the target before production.

---

## Development (this repo)

```sh
make unit       # 29 handler tests under Node (no licence needed)
make contract   # schema contract over a generated record
make check      # unit + contract
make up         # demo stack: NGINX Plus + httpbin + UDP listener (needs licence)
make e2e        # curl/jq assertions against the demo stack
make down
```

`make unit-nginx` runs the same suite inside nginx at `/__unit` on a licensed
host. The unit harness is test-only: never expose `/__unit` in production.

## Kubernetes test deployment

`deploy/kubernetes/` runs the logger with native `auth_jwt` and a generated HS256
JWKS. See `deploy/kubernetes/README.md` for apply, teardown and the observed 401/200
matrix.

## Install on a VM

`deploy/vm/install.sh` installs the module, snippets and rotation into an
existing NGINX Plus host; `deploy/vm/README.md` covers wiring, the demo server
and troubleshooting.
