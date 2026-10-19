#!/bin/sh
# lab8a_sim_registry.sh — the mini-nvcr.io: make plain `docker push nvcr.io/...`
# work against a local fake registry on the runner, with no special flags.
#
# Subcommands:
#   up     wire the credential helper into every docker resolution path (CLI env,
#          daemon PATH, daemon config, daemon env via systemd drop-in), make the
#          name nvcr.io resolve locally with genuinely trusted TLS, start
#          registry:2 on :443 demanding token auth with its realm at the vm1
#          token service (tunnel B), and wait for the 401 challenge
#   swap   point the daemon's drop-in at the CURRENT NGC_OIDC_ACCESS_TOKEN and
#          restart the daemon (live-restore keeps sim-nvcr up), then re-check
#          the challenge — the refresh step's daemon half
#
# Inputs (environment):
#   NGC_OIDC_ACCESS_TOKEN  the exchanged credential (up: initial; swap: refreshed)
#   TOKEN_SVC_URL          stage-2 token service base (tunnel B), no trailing slash
#
# Both subcommands are safe to re-run: `up` removes any previous sim-nvcr and
# guards the /etc/hosts entry.

set -eu

SIM_NAME="sim-nvcr"
DROP_IN="/etc/systemd/system/docker.service.d/lab8a.conf"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_SRC="$script_dir/nvcr_oidc_init"
tls_dir="${RUNNER_TEMP:-/tmp}/lab8a-tls"

write_drop_in() {
    printf '[Service]\nEnvironment=NGC_OIDC_ACCESS_TOKEN=%s\n' "$NGC_OIDC_ACCESS_TOKEN" \
        | sudo tee "$DROP_IN" >/dev/null
    sudo chmod 600 "$DROP_IN"
}

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
    : "${NGC_OIDC_ACCESS_TOKEN:?NGC_OIDC_ACCESS_TOKEN is required (the exchanged credential)}"

    # 1. the helper where every resolution path finds it: the daemon spawns the
    #    helper from ITS environment and config, the CLI from its own (LAB8A §6)
    sudo install -m 755 "$HELPER_SRC" /usr/local/bin/docker-credential-ngc
    sudo mkdir -p /root/.docker
    printf '{"credHelpers":{"nvcr.io":"ngc"}}\n' | sudo tee /root/.docker/config.json >/dev/null
    sudo mkdir -p /etc/systemd/system/docker.service.d
    write_drop_in
    # live-restore: the refresh's `swap` restarts the daemon — sim-nvcr survives it
    if [ -f /etc/docker/daemon.json ]; then
        jq '. + {"live-restore": true}' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json >/dev/null
    else
        echo '{"live-restore": true}' | sudo tee /etc/docker/daemon.json >/dev/null
    fi

    # 2. the name nvcr.io means this box, with genuinely trusted TLS (no --insecure)
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
    sudo systemctl daemon-reload
    sudo systemctl restart docker
    grep -qE '^127\.0\.0\.1[[:space:]]+nvcr\.io$' /etc/hosts \
        || echo "127.0.0.1 nvcr.io" | sudo tee -a /etc/hosts

    # 3. the fake registry: token auth, realm at the vm1 token service (tunnel B),
    #    trusting that service's signing cert — the real registry's trust shape
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

    # 4. readiness: answering as a private registry (401 + WWW-Authenticate)
    wait_for_challenge
    curl -sSi https://nvcr.io/v2/ | grep -i www-authenticate
}

do_swap() {
    : "${NGC_OIDC_ACCESS_TOKEN:?NGC_OIDC_ACCESS_TOKEN is required (the refreshed credential)}"
    write_drop_in
    sudo systemctl daemon-reload
    sudo systemctl restart docker
    wait_for_challenge
    echo "daemon env swapped; sim registry still answering (challenge 401)"
}

case "${1:-}" in
    up) do_up ;;
    swap) do_swap ;;
    *) echo "usage: $0 [up|swap]" >&2; exit 1 ;;
esac
