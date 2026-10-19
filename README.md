# oidc-playground

A playground for OIDC and keyless-auth experiments in GitHub Actions:
minting CI identity tokens, RFC 8693 token exchange, docker credential
helpers, and container pushes without stored secrets.

Each `lab*` workflow (`.github/workflows/`) is a self-contained,
manually dispatched experiment; shared pieces live in `actions/` and
`.github/scripts/`. Experiments run against public cloud registries and
a token-exchange endpoint supplied per dispatch.
