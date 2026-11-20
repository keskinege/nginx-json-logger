# jsonlog on Kubernetes — test deployment

A standalone **NGINX Plus** pod running `jsonlog`, plus httpbin and a generated
HS256 JWKS. `auth_jwt` is enabled on `/api/` so the logger's 401 explanation
path is exercised end to end.

## Prerequisites

- a Kubernetes cluster and `kubectl` context
- `jq`, `openssl`
- a namespace (`SRCNS`) holding:
  - `regcred` — pull secret for the NGINX Plus registry
  - `nplus-license` — secret of type `nginx.com/license`, key `license.jwt`

## Apply

```sh
CTX=my-context SRCNS=my-namespace ./apply.sh
# optional: IMAGE=<your plus image>
```

Creates namespace `jsonlog-test` with:

| Resource | Purpose |
|---|---|
| `secret/regcred`, `secret/nplus-license` | copied from `$SRCNS` (owner refs stripped) |
| `secret/jsonlog-demo` | generated HS256 key, reused across re-applies |
| `configmap/jsonlog-config` | nginx.conf, http.conf, location/no-body, jsonlog.js, jwks.json |
| `deploy/jsonlog-httpbin` + `svc` | upstream |
| `deploy/jsonlog-nginx` + `svc` | Plus + jsonlog, 8080 → 80 |
| `location /_jwks` | internal static JWKS (`auth_jwt_key_request`) |
| `location /api/` | `auth_jwt` + key cache + `auth_jwt_require` issuer map |
| `location /open/` | logging only |

The default image is `nginx-plus-ingress:5.6.3` (nginx 1.31.x Plus, njs and
`auth_jwt`). It is **amd64-only**; the pod carries
`nodeSelector: kubernetes.io/arch: amd64`.

## Test

```sh
kubectl --context "$CTX" -n jsonlog-test port-forward svc/jsonlog-nginx 18081:80 &
B=http://localhost:18081
SECRET=$(kubectl --context "$CTX" -n jsonlog-test get secret jsonlog-demo -o jsonpath='{.data.secret}' | base64 -d)

T=$(JWT_SECRET=$SECRET node ../../test/e2e/mint-hs256.mjs)
EXP=$(JWT_SECRET=$SECRET node ../../test/e2e/mint-hs256.mjs --exp-in -60)
BAD=$(JWT_SECRET=$SECRET node ../../test/e2e/mint-hs256.mjs --secret wrong)
AUD=$(JWT_SECRET=$SECRET node ../../test/e2e/mint-hs256.mjs --aud other)
ISS=$(JWT_SECRET=$SECRET node ../../test/e2e/mint-hs256.mjs --iss https://other)

curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $T"   $B/api/get  # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $EXP" $B/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $BAD" $B/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AUD" $B/api/get  # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ISS" $B/api/get  # 401
curl -s -o /dev/null -w '%{http_code}\n' $B/api/get                                   # 401

kubectl --context "$CTX" -n jsonlog-test logs deploy/jsonlog-nginx -c nginx --tail=20 \
  | grep '^{' \
  | jq -c '{status:.response.status,verdict:.auth.verdict,
            errs:[.auth.validation.errors[].code],
            hint:.auth.validation.reason_hint,sub:.auth.jwt.claims.sub}'
```

Expected:

```
200  errs=[]                     valid
401  errs=["expired"]            expired
401  errs=[] hint=signature_or_key   bad signature (unverifiable)
200  errs=["audience_mismatch"]  wrong aud — auth_jwt does not check audience
401  errs=["issuer_mismatch"]    wrong iss — auth_jwt_require rejects
401  errs=["token_missing"]      no token
```

## Existing JWT configs: what to watch

Typical NGINX Plus deployments validate **signature, expiry and issuer** and
leave audience unchecked. Consequences when adding the logger:

| Pattern | Effect on the record |
|---|---|
| `auth_jwt` with the default Bearer source | decoded, reasons reported |
| `auth_jwt "" token=$some_var` (cookie / custom header) | `token_missing` — only `Authorization: Bearer` is decoded |
| `auth_jwt_require` issuer map | failures appear as `issuer_mismatch` when `$jl_expected_issuer` is set |
| OIDC policy (ID token in a cookie) | `token_missing` unless the token is exposed as a Bearer header |

Add expectations per location to name issuer/audience mismatches:

```nginx
set $jl_expected_issuer   "https://idp.example.com/realms/prod";
set $jl_expected_audience "api";
set $jl_allowed_algs      "RS256";
```

## Teardown

```sh
kubectl --context "$CTX" delete ns jsonlog-test
```

## Deployment pitfalls

- The Plus ingress image is amd64-only; arm64 nodes fail with
  `no match for platform in manifest`.
- Its `/usr/sbin/nginx` carries `cap_net_bind_service`; running with
  `allowPrivilegeEscalation: false` makes `exec` fail with EPERM (exit 255).
- Copied secrets must have `ownerReferences` removed or External Secrets
  garbage-collects them.
