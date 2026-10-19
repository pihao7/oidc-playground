#!/bin/sh
# lab8a_sim_registry.sh — make plain `docker push nvcr.io/...` work against a
# LOCAL registry on the runner, with no special flags.
#
# The registry is NOT simulated — it is the real Docker registry: registry:2 is
# docker/distribution, the standard registry implementation. The /v2/ API, the
# 401 challenge, the bearer-token
# enforcement, manifests and blobs are all the real thing. What stands in for
# the real nvcr.io service is only WHERE it lives and WHO vouches for
# credentials, and each substitution is a config-level trick:
#   1. the NAME — /etc/hosts maps nvcr.io -> 127.0.0.1, so the real registry
#      answers at the real hostname; docker's config needs no exceptions
#   2. the TLS — a throwaway CA signs a server cert FOR the name nvcr.io and
#      the CA goes into the system trust store, so the daemon's and curl's real
#      certificate verification passes (no --insecure anywhere)
#   3. the AUTH — the registry's token-auth config (auth.token) points its
#      realm at the vm1 token service (stage 2, the registry's auth-endpoint
#      stand-in) and sets rootcertbundle to that service's signing cert: the
#      same trust shape a real registry has with its token service. The
#      registry then enforces the tokens that service issues, itself.
#
# Credential resolution stays CLIENT-side: the docker CLI resolves pull/push
# credentials itself and spawns the helper from the step's environment — the
# helper is a client-side mechanism, and the refresh flow (nvcr_docker swapping
# NGC_OIDC_ACCESS_TOKEN in the step env, retried op included) depends on it.
# Verified on runner docker 28.0.4: this holds under both image stores, so the
# classic store is a conservative default, not a requirement — it also
# sidesteps containerd-store differences (e.g. it ignores insecure-registries).
# Set LAB8A_IMAGE_STORE=containerd to run the lab on the containerd store.
#
# Subcommand:
#   up     set the image store (LAB8A_IMAGE_STORE, classic|containerd, default
#          classic), make the name nvcr.io resolve locally with genuinely
#          trusted TLS, start registry:2 on :443 demanding token auth with its
#          realm at the vm1 token service (tunnel B), and wait for the 401
#          challenge
#
# Inputs (environment):
#   TOKEN_SVC_URL          stage-2 token service base (tunnel B), no trailing slash
#
# Safe to re-run: removes any previous sim-nvcr and guards the /etc/hosts entry.

set -eu

SIM_NAME="sim-nvcr"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tls_dir="${RUNNER_TEMP:-/tmp}/lab8a-tls"

wait_for_challenge() {
    for i in $(seq 1 30); do
        [ "$(curl -sS -o /dev/null -w '%{http_code}' https://nvcr.io/v2/ 2>/dev/null || true)" = "401" ] && return 0
        sleep 1
    done
    echo "sim registry did not start answering (no 401 challenge from https://nvcr.io/v2/)" >&2
    return 1
}

do_up() {
    : "${TOKEN_SVC_URL:?TOKEN_SVC_URL is required (stage-2 token service base, tunnel B)}"
    TOKEN_SVC_URL="${TOKEN_SVC_URL%/}"

    # 1. image store: classic by default (LAB8A_IMAGE_STORE=containerd opts in
    #    to the containerd store) — see the header note on credential
    #    resolution. (Merge, don't clobber: keep any other feature flags the
    #    runner image set.)
    image_store="${LAB8A_IMAGE_STORE:-classic}"
    case "$image_store" in
        classic)    snapshotter=false ;;
        containerd) snapshotter=true ;;
        *) echo "LAB8A_IMAGE_STORE must be 'classic' or 'containerd'" >&2; exit 2 ;;
    esac
    if [ -f /etc/docker/daemon.json ]; then
        jq --argjson v "$snapshotter" '.features = ((.features // {}) + {"containerd-snapshotter": $v})' \
            /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json >/dev/null
    else
        printf '{"features": {"containerd-snapshotter": %s}}\n' "$snapshotter" | sudo tee /etc/docker/daemon.json >/dev/null
    fi
    sudo systemctl restart docker

    # 2. the name nvcr.io means this box, and the TLS is genuinely trusted:
    #    a throwaway CA issues a server cert FOR the name nvcr.io, and the CA
    #    installed into the system store makes the daemon's and curl's real
    #    certificate verification pass against the local registry (no --insecure)
    mkdir -p "$tls_dir"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$tls_dir/ca.key" -out "$tls_dir/ca.crt" -subj "/CN=lab8a-sim-ca"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$tls_dir/nvcr.io.key" -out "$tls_dir/nvcr.io.csr" \
        -subj "/CN=nvcr.io" -addext "subjectAltName=DNS:nvcr.io"
    printf 'subjectAltName=DNS:nvcr.io\n' > "$tls_dir/ext.cnf"
    openssl x509 -req -days 2 \
        -in "$tls_dir/nvcr.io.csr" -CA "$tls_dir/ca.crt" -CAkey "$tls_dir/ca.key" \
        -out "$tls_dir/nvcr.io.crt" -extfile "$tls_dir/ext.cnf"
    sudo cp "$tls_dir/ca.crt" /usr/local/share/ca-certificates/lab8a-sim-ca.crt
    sudo update-ca-certificates
    grep -qE '^127\.0\.0\.1[[:space:]]+nvcr\.io$' /etc/hosts \
        || echo "127.0.0.1 nvcr.io" | sudo tee -a /etc/hosts

    # 3. the REAL Docker registry (registry:2 = docker/distribution), published
    #    on :443 and configured for token auth: the challenge's realm points at
    #    the vm1 token service (tunnel B) — the auth endpoint stand-in — and
    #    rootcertbundle tells the registry which signer's bearer tokens to
    #    accept (that service's cert, fetched from its /cert.pem). The registry
    #    then enforces those tokens itself; nothing here patches the registry.
    docker rm -f "$SIM_NAME" >/dev/null 2>&1 || true
    curl -sfS "$TOKEN_SVC_URL/cert.pem" -o "$tls_dir/token-root.pem"
    head -1 "$tls_dir/token-root.pem" | grep -q "BEGIN CERTIFICATE"
    cat > "$tls_dir/registry-config.yml" <<YAML
version: 0.1
log:
  level: info
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :5000
  tls:
    certificate: /etc/registry/tls/nvcr.io.crt
    key: /etc/registry/tls/nvcr.io.key
auth:
  token:
    realm: $TOKEN_SVC_URL/auth
    service: registry
    issuer: https://nvcr-token-proxy-poc.local
    rootcertbundle: /etc/registry/token-root.pem
YAML
    docker run -d --name "$SIM_NAME" -p 443:5000 \
        -v "$tls_dir/registry-config.yml":/etc/docker/registry/config.yml:ro \
        -v "$tls_dir/token-root.pem":/etc/registry/token-root.pem:ro \
        -v "$tls_dir/nvcr.io.crt":/etc/registry/tls/nvcr.io.crt:ro \
        -v "$tls_dir/nvcr.io.key":/etc/registry/tls/nvcr.io.key:ro \
        registry:2

    # 4. readiness: the registry's OWN 401 + WWW-Authenticate challenge — the
    #    normal "tell me who you are" of a private registry, nothing mocked
    wait_for_challenge
    curl -sSi https://nvcr.io/v2/ | grep -i www-authenticate
}

case "${1:-}" in
    up) do_up ;;
    *) echo "usage: $0 up" >&2; exit 1 ;;
esac
