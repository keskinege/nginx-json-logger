# jsonlog on a VM

Install and use the logger on an existing **NGINX Plus** host. Two phases: install
the module and wire the include, then (optionally) install a self-contained demo
that exercises native `auth_jwt` with the dummy HS256 IdP.

## Prerequisites

| Requirement | Check |
|---|---|
| NGINX Plus r33+ | `nginx -v` → `nginx/1.31.x (nginx-plus-r37)` |
| njs ≥ 0.9.9 | `nginx -V 2>&1 \| grep -i njs`; `readRequestArrayBuffer` needs 0.9.9 |
| njs module installed | `apt install nginx-plus-module-njs` |
| `auth_jwt` built in | `nginx -V 2>&1 \| grep auth_jwt` |
| valid licence | `/etc/nginx/license.jwt` (or beside a custom `-c` config) |
| `jq`, `openssl` | for the demo and log inspection |

OSS nginx is not supported: `js_access` needs the njs module and `auth_jwt` is
Plus-only.

## 1. Copy the repo to the VM

```sh
scp -r logger user@vm:~/logger
# or: git clone <repo> && cd logger
```

## 2. Install files

```sh
cd ~/logger
sudo ./deploy/vm/install.sh
```

Installs:

```
/etc/nginx/njs/jsonlog.js
/etc/nginx/conf.d/jsonlog/{http,location,no-body,syslog}.conf
/etc/logrotate.d/nginx-jsonlog
```

It does **not** touch `nginx.conf`. It prints the include you need.

## 3. Wire it in

Main context, if the njs module is not already loaded by `modules-enabled/`:

```nginx
load_module modules/ngx_http_js_module.so;
```

Inside `http {}`, **before** `include /etc/nginx/conf.d/*.conf;` (the demo lives
in that glob and references the imported module):

```nginx
include /etc/nginx/conf.d/jsonlog/http.conf;
```

Per logged location:

```nginx
location /api/ {
    include /etc/nginx/conf.d/jsonlog/location.conf;   # full capture
    proxy_pass http://backend;
}

location /events/ {
    include /etc/nginx/conf.d/jsonlog/no-body.conf;    # SSE / large downloads
    proxy_pass http://backend;
}
```

Then:

```sh
sudo nginx -t && sudo nginx -s reload
```

## 4. Logging only (JWT already configured)

If the host already validates tokens, install the logger without touching auth:

```sh
sudo ./deploy/vm/install.sh --js-only      # alias: --no-jwt
```

That installs `jsonlog.js`, the four snippets and rotation, and **skips**:

- the `auth_jwt` capability check,
- the demo server and `jwks.json`,
- any `auth_jwt` / `auth_jwt_require` directives.

Wire `include /etc/nginx/conf.d/jsonlog/location.conf;` into the locations that
already run `auth_jwt` (or any other validator). Do not add `auth_jwt` unless it
is missing.

To have issuer/audience mismatches reported, add expectations to those locations:

```nginx
set $jl_expected_issuer   "https://idp.example.com/realms/prod";
set $jl_expected_audience "api";
set $jl_allowed_algs      "RS256";
```

`--js-only` and `--demo` are mutually exclusive.

## 5. Demo (optional)

The demo installs a server on `:8080` with `auth_jwt` against the static
`deploy/vm/jwks.json`. That key (`kid 0001`, secret `fantasticjwt`) is public and
demo-only — never use it outside this demo.

```sh
sudo ./deploy/vm/install.sh --demo --test
```

`--demo` refuses to run until `http.conf` is included (otherwise `nginx -t`
would fail). The demo file lands in `conf.d/jsonlog-demo.conf`, which the normal
`include /etc/nginx/conf.d/*.conf;` picks up.

```sh
cd ~/logger/deploy/vm
TOKEN=$(./mint-hs256.sh)
EXP=$(./mint-hs256.sh --exp-in -60)
BAD=$(./mint-hs256.sh --secret wrong)
AUD=$(./mint-hs256.sh --aud other)
ISS=$(./mint-hs256.sh --iss https://other)

curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" localhost:8080/api/get  # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $EXP"   localhost:8080/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $BAD"   localhost:8080/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AUD"   localhost:8080/api/get  # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ISS"   localhost:8080/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/get                                    # 401
```

Expected records:

```
200  errs=[]                     valid
401  errs=["expired"]            expired
401  errs=[] hint=signature_or_key   bad signature (unverifiable)
200  errs=["audience_mismatch"]  wrong aud — auth_jwt does not check audience
401  errs=["issuer_mismatch"]    wrong iss — auth_jwt_require rejects
401  errs=["token_missing"]      no token
```

## 6. Production settings

**Transport.** Default is a file log. For UDP:

```nginx
# server{} or location{}
set $jl_transport syslog;
include /etc/nginx/conf.d/jsonlog/syslog.conf;
```

Syslog is UDP-only, 2 KiB body preset, ~8 KiB record budget.

**Rotation** is installed by `install.sh` (daily, 14, `USR1`).

**Kill switch** — metadata only, no bodies:

```nginx
set $jl_bodies 0;
```

**Expectations** for the validation observations:

```nginx
set $jl_expected_issuer   "https://idp.example.com/realms/prod";
set $jl_expected_audience "api";
set $jl_allowed_algs      "RS256";
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `nginx -t`: unknown directive `js_access` | njs older than 0.9.9, or module not loaded |
| `nginx -t`: unknown directive `auth_jwt` | OSS nginx, not Plus |
| `license file is required` though the file exists | Plus started with `-c <path>` looks for `license.jwt` **beside that config** |
| `js: SyntaxError: Token "of" not supported` | njs build lacks `for…of`; this repo already uses index loops — reinstall `jsonlog.js` |
| every record is `{"event":"log_error"}` | check `error_log` for `emit_failed`; usually a stale `jsonlog.js` |
| `token_missing` for OIDC/cookie auth | the logger reads only `Authorization: Bearer` |
| SELinux denies reading `/etc/nginx/njs` | `chcon -Rt httpd_config_t /etc/nginx/njs` (or the nginx equivalent) |

## Uninstall

```sh
sudo rm -rf /etc/nginx/njs/jsonlog.js /etc/nginx/conf.d/jsonlog \
            /etc/nginx/conf.d/jsonlog-demo.conf /etc/logrotate.d/nginx-jsonlog
# remove the include line, then:
sudo nginx -t && sudo nginx -s reload
```
