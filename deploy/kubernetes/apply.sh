#!/usr/bin/env bash
#
# Deploy the jsonlog demo to Kubernetes.
# Requires: kubectl, jq, openssl.
#
#   CTX=my-context SRCNS=my-namespace ./apply.sh
#
# SRCNS must contain:
#   - an NGINX Plus licence secret (default name: nplus-license, key license.jwt)
#   - an image pull secret for the Plus registry (default name: regcred)
#
# Optional: IMAGE=<plus image>  (default: nginx-plus-ingress:5.6.3)
#
set -euo pipefail

CTX=${CTX:?set CTX to your kube context}
SRCNS=${SRCNS:?set SRCNS to the namespace holding regcred and the Plus licence}
IMAGE=${IMAGE:-private-registry.nginx.com/nginx-ic-nap-v5/nginx-plus-ingress:5.6.3}
NS=jsonlog-test

SRC=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$SRC/deploy/kubernetes"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

kubectl --context "$CTX" apply -f "$HERE/namespace.yaml"

# Copy pull + licence secrets, stripping owner refs so External Secrets does
# not garbage-collect the copies in the new namespace.
for s in regcred nplus-license; do
    kubectl --context "$CTX" -n "$SRCNS" get secret "$s" -o json \
        | jq 'del(.metadata.namespace, .metadata.uid, .metadata.resourceVersion,
                  .metadata.creationTimestamp, .metadata.managedFields, .metadata.selfLink,
                  .metadata.ownerReferences, .metadata.annotations, .metadata.labels)' \
        | kubectl --context "$CTX" -n "$NS" apply -f -
done

# Demo HS256 key is public and committed: deploy/kubernetes/jwks.json.

kubectl --context "$CTX" -n "$NS" create configmap jsonlog-config \
    --from-file=nginx.conf="$HERE/nginx.conf" \
    --from-file=http.conf="$HERE/http.conf" \
    --from-file=location.conf="$SRC/conf/jsonlog/location.conf" \
    --from-file=no-body.conf="$SRC/conf/jsonlog/no-body.conf" \
    --from-file=jsonlog.js="$SRC/njs/jsonlog.js" \
    --from-file=jwks.json="$HERE/jwks.json" \
    --dry-run=client -o yaml | kubectl --context "$CTX" -n "$NS" apply -f -

sed "s|^          image: .*|          image: $IMAGE|" "$HERE/deployment.yaml" > "$TMP/deployment.yaml"
kubectl --context "$CTX" -n "$NS" apply \
    -f "$HERE/httpbin.yaml" -f "$TMP/deployment.yaml" -f "$HERE/service.yaml"

kubectl --context "$CTX" -n "$NS" rollout status deploy/jsonlog-httpbin --timeout=180s
kubectl --context "$CTX" -n "$NS" rollout status deploy/jsonlog-nginx --timeout=180s
kubectl --context "$CTX" -n "$NS" get pods,svc -o wide

cat <<EOF

Demo key (public, demo only): deploy/kubernetes/jwks.json
  jq -r '.keys[0].k' deploy/kubernetes/jwks.json | tr '_-' '/+' | openssl base64 -d -A

Mint a token and test:
  node $SRC/test/e2e/mint-hs256.mjs
  kubectl --context $CTX -n $NS port-forward svc/jsonlog-nginx 18081:80
EOF
